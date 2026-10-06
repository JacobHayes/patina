//! Structured outcome classification and failure signatures.

use super::Signature;
use super::generation::SIGKILL;
use super::state::json_required_str;
use std::collections::BTreeMap;

// ===========================================================================
// Classifier (pure) + signatures
// ===========================================================================

/// The per-generation outcome classes, in descending severity. An explicit
/// finding is never downgraded, and a nonzero exit is never silently OK.
///
/// The declaration order is the severity order: [`ClassifyRules`] iterates its
/// declared classes through it, so two matching declarations always resolve to
/// the more severe one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CampaignClass {
    /// The run completed clean (exit 0, no finding).
    Ok,
    /// A system-under-test safety/assertion violation: a `VerdictKind::Violation`
    /// the guest reported through the verdict ABI (which `always!` lowers to), or
    /// a class a campaign spec declared for this guest ([`ClassifyRules`]).
    Violation,
    /// A liveness-watchdog violation: a `runtime_findings[]` entry with
    /// `source=liveness` — a virtual-time no-progress wedge.
    Liveness,
    /// A configured filesystem fault class was vacuous: eligible filesystem I/O
    /// occurred, but an enabled fs error/short-I/O fault class applied zero
    /// effects. This is a coverage failure, not a SUT finding.
    VacuousFsFault,
    /// A configured DNS fault class was vacuous: the guest resolved defined names
    /// often enough for an enabled failure/latency class to have fired several
    /// times over, yet it applied zero effects. A coverage failure, not a SUT
    /// finding — and its own class rather than a shared "vacuous fault" bucket so
    /// a campaign report says which fault plane went inert.
    VacuousDnsFault,
    /// A configured network fault class was vacuous: fault-eligible traffic
    /// (sends, connects, or stream ops) occurred often enough for an enabled
    /// drop/jitter/latency/duplicate/connect-refuse/reset/partition class to have
    /// fired several times over, yet it applied zero effects. A coverage
    /// failure, not a SUT finding, and its own class for the same reason
    /// [`CampaignClass::VacuousDnsFault`] is not folded into
    /// [`CampaignClass::VacuousFsFault`].
    VacuousNetFault,
    /// A configured entropy fault class was vacuous: fault-eligible entropy
    /// requests occurred often enough for the enabled failure knob to have fired
    /// several times over, yet it applied zero effects. A coverage failure, not a
    /// SUT finding, and its own class for the same reason
    /// [`CampaignClass::VacuousDnsFault`] is not folded into
    /// [`CampaignClass::VacuousFsFault`].
    VacuousEntropyFault,
    /// A configured clock fault class was vacuous: fault-eligible realtime-epoch
    /// reads occurred often enough for the enabled jump knob to have applied a
    /// non-zero offset several times over, yet it applied zero effects. A
    /// coverage failure, not a SUT finding, and its own class for the same
    /// reason [`CampaignClass::VacuousDnsFault`] is not folded into
    /// [`CampaignClass::VacuousFsFault`].
    VacuousClockFault,
    /// A configured custom-op fault class was vacuous: either the generation
    /// executed no fault-eligible custom operation at all, or it executed enough
    /// of them for the enabled failure knob to have fired several times over yet
    /// it applied zero faults. The zero-opportunity half has no analogue in the
    /// classes above, and that is the point — a fault-eligible custom op exists
    /// only because the guest declared one, so arming the knob over a guest or a
    /// path that offers none is a coverage claim with nothing behind it.
    VacuousCustomOpFault,
    /// `--swarm` was requested for a generation with no swarm-maskable fault class
    /// enabled, so the draw had zero candidates: it neither kept nor dropped
    /// anything and the generation explored exactly what a non-swarm generation
    /// explores. A coverage failure like [`CampaignClass::VacuousFsFault`] — a
    /// campaign that asked for fault-subset exploration and got none must not
    /// read as a clean covered run.
    VacuousSwarm,
    /// The guest aborted itself: a SIGABRT (or exit 134) that the envelope did
    /// NOT attribute to a patina refusal, so it is the guest's own doing — a
    /// `panic = "abort"` invariant failure, an `assert!`, a bare `abort()`. A
    /// finding bucket, not infra noise: with patina's own refusals
    /// envelope-attributed ([`CampaignClass::FailClosedAbort`]), an unattributed
    /// abort can only have come from the system under test. A preceding
    /// `abort_intent`/`violation` verdict enriches the signature but is not
    /// required for the class to fire.
    GuestAbort,
    /// Patina fail-closed refusal: the envelope carries a `refusal` record — a
    /// fingerprint/trace mismatch, a duplicate buggify label, a
    /// declared-but-never-called setup gate, a runtime that refused to
    /// initialize, a shim fatal abort.
    FailClosedAbort,
    /// The `--starve` supervisor stall backstop killed a wedged run (exit 111).
    ///
    /// NOT a finding — see [`CampaignClass::is_finding`]. The backstop only arms
    /// under `--starve`, so every exit 111 is a run that patina's OWN injector
    /// was holding tasks off in when it stopped making progress, and patina
    /// cannot today say whether the guest livelocks on its own or whether the
    /// hold plus an uninstrumented spin loop wedged it. Its own class rather than
    /// folded into [`CampaignClass::Infra`], because which generations the
    /// injector wedged is exactly what an operator tunes
    /// `--starve-scale-permille` against.
    StarvationStall,
    /// Harness/build infrastructure failure, not a SUT finding: the campaign's
    /// wall-clock backstop killed the generation, or the child `cargo patina run`
    /// never produced a `patina.result/v1` envelope at all (a build failure, a
    /// pre-run gate refusal, a supervisor error — patina could not report a
    /// result for this generation).
    Infra,
    /// A nonzero exit that matched no class above — an unknown/unparseable outcome.
    /// Loud and always a failure, so a novel failure mode is surfaced for triage
    /// rather than silently dropped or mislabeled.
    Unclassified,
}

impl CampaignClass {
    /// Every class, in severity order. A new variant that is not added here fails
    /// [`every_class_round_trips_its_token`].
    pub const ALL: &'static [CampaignClass] = &[
        CampaignClass::Ok,
        CampaignClass::Violation,
        CampaignClass::Liveness,
        CampaignClass::VacuousFsFault,
        CampaignClass::VacuousDnsFault,
        CampaignClass::VacuousNetFault,
        CampaignClass::VacuousEntropyFault,
        CampaignClass::VacuousClockFault,
        CampaignClass::VacuousCustomOpFault,
        CampaignClass::VacuousSwarm,
        CampaignClass::GuestAbort,
        CampaignClass::FailClosedAbort,
        CampaignClass::StarvationStall,
        CampaignClass::Infra,
        CampaignClass::Unclassified,
    ];

    pub const fn as_str(&self) -> &'static str {
        match self {
            CampaignClass::Ok => "OK",
            CampaignClass::Violation => "VIOLATION",
            CampaignClass::Liveness => "LIVENESS",
            CampaignClass::VacuousFsFault => "VACUOUS_FS_FAULT",
            CampaignClass::VacuousSwarm => "VACUOUS_SWARM",
            CampaignClass::VacuousDnsFault => "VACUOUS_DNS_FAULT",
            CampaignClass::VacuousNetFault => "VACUOUS_NET_FAULT",
            CampaignClass::VacuousEntropyFault => "VACUOUS_ENTROPY_FAULT",
            CampaignClass::VacuousClockFault => "VACUOUS_CLOCK_FAULT",
            CampaignClass::VacuousCustomOpFault => "VACUOUS_CUSTOM_OP_FAULT",
            CampaignClass::GuestAbort => "GUEST_ABORT",
            CampaignClass::FailClosedAbort => "FAIL_CLOSED_ABORT",
            CampaignClass::StarvationStall => "STARVATION_STALL",
            CampaignClass::Infra => "INFRA",
            CampaignClass::Unclassified => "UNCLASSIFIED",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        CampaignClass::ALL
            .iter()
            .copied()
            .find(|class| class.as_str() == value)
    }

    /// The `fault_reports{}` plane whose `vacuous` bit fires this class, for the
    /// per-plane coverage-failure classes.
    const fn vacuous_plane(&self) -> Option<&'static str> {
        match self {
            CampaignClass::VacuousFsFault => Some("fs"),
            CampaignClass::VacuousDnsFault => Some("dns"),
            CampaignClass::VacuousNetFault => Some("net"),
            CampaignClass::VacuousEntropyFault => Some("entropy"),
            CampaignClass::VacuousClockFault => Some("clock"),
            CampaignClass::VacuousCustomOpFault => Some("custom_op"),
            CampaignClass::VacuousSwarm => Some("swarm"),
            _ => None,
        }
    }

    /// Whether this class is a failure the campaign must surface (everything but
    /// `OK`).
    pub const fn is_failure(&self) -> bool {
        !matches!(self, CampaignClass::Ok)
    }

    /// Whether this class is a FINDING — something learned about the system under
    /// test — as opposed to a condition of the run itself. `INFRA` is the
    /// original one that is not: a timeout, a host-side SIGKILL, a build failure,
    /// and patina's own recorder giving out all say the generation produced no
    /// answer. They are still surfaced and still deduped, but they must not spend
    /// the campaign's novel-signature budget, which exists to say "this many
    /// DISTINCT BUGS were found".
    ///
    /// `STARVATION_STALL` joins it, by the same argument that moved the host
    /// SIGKILL and patina's own recorder failures out of the bug classes. The
    /// stall backstop arms ONLY under `--starve`, so every exit 111 is a run that
    /// patina's own injector was holding tasks off in — and the wedge is a
    /// documented limitation of that injector rather than a fact about the guest:
    /// std's spin loops carry no yield point, so once a spinner starts while the
    /// lock holder is held off, the scheduler gets no further decision, its aging
    /// cap can never fire, and the run is stuck no matter how briefly the hold
    /// was meant to last. Measured on turso's `turso_stress`: two holds of at
    /// most four decisions wedge a run that completes in 26 s at the same seed
    /// with starvation off, and it is still wedged 15 minutes later. Filing that
    /// as a distinct bug found spends a novel-signature slot on patina's own
    /// exploration knob and prints a reproduce command whose "failure" is the
    /// harness.
    ///
    /// What this deliberately does NOT do is erase the distinction the class
    /// exists for. A guest that livelocks on its own, where the scheduler still
    /// gets decisions to make, is caught by the runtime's liveness watchdog and
    /// filed as [`CampaignClass::Liveness`] — a finding, and still counted as
    /// one. A wedge that only exists because patina was starving the guest stays
    /// visible under its own name, which is what an operator reads to tune
    /// `--starve-scale-permille`, rather than being flattened into the
    /// timeout/build-failure bucket. Telling the two apart INSIDE exit 111 needs
    /// a progress signal the supervisor does not have today — the scheduler's
    /// decision counter, which a wedged run freezes and a merely slow one does
    /// not — and until it does, the honest reading of exit 111 is "no answer",
    /// not "a bug".
    pub const fn is_finding(&self) -> bool {
        self.is_failure() && !matches!(self, CampaignClass::Infra | CampaignClass::StarvationStall)
    }
}

/// The exit code a raw SIGABRT surfaces as (128 + SIGABRT(6)). A guest that dies
/// on SIGABRT has either hit a patina refusal (the shim aborts fail-closed via
/// `std::process::abort()`) or aborted itself; the envelope's `refusal` field is
/// what tells the two apart (§4.4 of the outcome-channel arc).
pub(super) const SIGABRT: i32 = 6;
pub(super) const SIGABRT_EXIT: i32 = 128 + SIGABRT;

/// The hardware/OS fault signals: the guest died executing bad code, which is a
/// GUEST failure but not an abort — it never reached `abort()` and never got to
/// say anything. Named so a signature can say WHICH fault instead of dedupping
/// every crash onto whatever text happened to be last.
const FAULT_SIGNALS: &[(i32, &str)] = &[
    (4, "SIGILL"),
    (7, "SIGBUS"),
    (8, "SIGFPE"),
    (11, "SIGSEGV"),
    (31, "SIGSYS"),
];

/// The shape a host-killed generation always gets. One constant, because the
/// campaign summary counts these by it: they are an operational signal (the box
/// is out of memory), not a result.
pub(super) const HOST_KILL_SHAPE: &str = "killed by SIGKILL (host-side; not a guest failure)";

/// The shape a generation gets when patina's own end-of-run recorder failed, as
/// the campaign summary counts them by it. Kept in sync with the
/// `shutdown_failure` refusal class `output.rs` assigns.
pub(super) const SHUTDOWN_FAILURE_SHAPE: &str = "refusal class=shutdown_failure";

/// The refusal class patina's own end-of-run recorder failure carries.
const SHUTDOWN_FAILURE_CLASS: &str = "shutdown_failure";
/// The refusal class for a run whose trace CHANNEL failed — patina could not
/// open, read, or rename the recorder's own scratch file. An operational
/// condition of the host, in the same family as a timeout or an OOM kill.
pub(super) const TRACE_UNAVAILABLE_CLASS: &str = "trace_unavailable";

/// One verdict the generation reported through the verdict ABI, reduced to what
/// classification, signatures and `minimize`'s auto-target need. Lifted from the
/// envelope's `verdicts[]`.
///
/// `detail` is deliberately not carried: it is free-form per-call payload (an
/// outcome digest, a job id, a byte offset), so two runs of the same failure
/// routinely disagree on it. Identity is `(kind, label)` — the aggregation key
/// the arc took from Antithesis and the one `sites.json` labels already share.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerdictFacts {
    /// The `VerdictKind` token (`violation`, `pass`, `abort_intent`).
    pub kind: String,
    pub label: String,
}

impl VerdictFacts {
    /// Whether this verdict announces a failure rather than a confirmation.
    ///
    /// `violation` (an invariant the guest found broken) and `abort_intent` (a
    /// deliberate fail-closed stop the guest is about to take) are the kinds that
    /// describe something going wrong; `pass` is the guest reporting that a
    /// property held, which is not a failure anything can be minimized against.
    pub fn is_failure(&self) -> bool {
        self.kind == "violation" || self.kind == "abort_intent"
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "kind": self.kind.clone(), "label": self.label.clone() })
    }

    pub(super) fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "notable run verdict must be an object".to_string())?;
        let facts = VerdictFacts {
            kind: json_required_str(object, "kind")?.to_string(),
            label: json_required_str(object, "label")?.to_string(),
        };
        if facts.to_json() != *value {
            return Err("notable run verdict is not in canonical lossless form".to_string());
        }
        Ok(facts)
    }
}

/// **The recognition primitive** (outcome-channel arc §4.5): the verdicts a
/// `patina.result/v1` envelope reports, in call order.
///
/// One mechanism, two consumers asking different questions of it. The campaign
/// classifies *from* this set — the multi-way, open "which class did this
/// generation land in?" of [`built_in_class`]. `minimize` captures a seed
/// generation's set as a fixed TARGET and asks the binary "does this candidate
/// still exhibit it?". Neither reimplements the other, so the classifier and the
/// reducer can never disagree about what a run reported.
pub fn recognize_verdicts(envelope: &serde_json::Value) -> Vec<VerdictFacts> {
    let string = |value: Option<&serde_json::Value>| {
        value
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    envelope
        .get("verdicts")
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| VerdictFacts {
                    kind: string(row.get("kind")),
                    label: string(row.get("label")),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// One runtime-detected finding, reduced to its attribution. Lifted from the
/// envelope's `runtime_findings[]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FindingFacts {
    /// `liveness` (the watchdog/converge oracle) or `schedule` (the vacuity
    /// diagnostics).
    pub source: String,
    pub kind: String,
    /// A simulator limitation is not a novel guest bug.
    pub known_limit: bool,
}

/// The **structured** outcome facts of one generation: the child run's
/// `patina.result/v1` envelope reduced to the fields classification reads, plus
/// the two facts only the campaign supervisor knows (whether it killed the
/// generation on the wall-clock backstop, and whether the child produced an
/// envelope at all).
///
/// Deliberately text-free. [`built_in_class`] is a pure function of this struct,
/// so no built-in class can ever be decided by a substring of guest output; the
/// captured streams live one level up in [`GenerationFacts`] and are reachable
/// only by the spec-declared pattern matcher ([`ClassifyRules`]) and by the
/// signature's last-resort fallback.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunFacts {
    /// The child process's exit status.
    pub exit_code: i32,
    /// The signal the guest died on, from `guest_exit.signal`. `exit_code` alone
    /// cannot express this (it is `128 + signal` there, the same value a guest
    /// could have returned deliberately).
    pub signal: Option<i32>,
    /// The campaign's wall-clock backstop killed this generation.
    pub timed_out: bool,
    /// The child emitted a `patina.result/v1` envelope. `false` means patina's
    /// own supervisor never reported a result for this generation.
    pub envelope: bool,
    /// `refusal.class` — patina's own fail-closed refusal, when patina refused.
    /// Its ABSENCE is what makes an abort the guest's own doing.
    pub refusal: Option<String>,
    /// `refusal.guest_exit_code` — the status the GUEST itself reached, when the
    /// refusal destroyed it. A `shutdown_failure` aborts the process from the
    /// atexit hook, so `exit_code`/`signal` above describe patina's abort rather
    /// than the guest; only this field can say whether the guest had already
    /// failed on its own. `None` when the refusal did not record one.
    pub refusal_guest_exit_code: Option<i32>,
    /// `verdicts[]`, in call order.
    pub verdicts: Vec<VerdictFacts>,
    /// The `fault_reports{}` planes whose `vacuous` bit is set.
    pub vacuous_planes: Vec<String>,
    /// `runtime_findings[]`.
    pub findings: Vec<FindingFacts>,
}

impl RunFacts {
    fn has_verdict(&self, kind: &str) -> Option<&VerdictFacts> {
        self.verdicts.iter().find(|verdict| verdict.kind == kind)
    }

    fn has_finding(&self, source: &str) -> Option<&FindingFacts> {
        self.findings
            .iter()
            .find(|finding| finding.source == source)
    }

    fn plane_vacuous(&self, plane: &str) -> bool {
        self.vacuous_planes.iter().any(|name| name == plane)
    }

    /// Whether this generation was killed from outside the guest. Only a real
    /// signal counts: `128 + 9` is a value a guest could have returned
    /// deliberately, and misreading one as a host kill would HIDE a finding —
    /// the opposite error from the one this rule exists to fix.
    fn host_killed(&self) -> bool {
        self.signal == Some(SIGKILL)
    }

    /// The name of the fault signal the guest died on, if it died on one.
    fn fault_signal(&self) -> Option<&'static str> {
        let signal = self.signal?;
        FAULT_SIGNALS
            .iter()
            .find(|(number, _)| *number == signal)
            .map(|(_, name)| *name)
    }

    /// Whether the guest died on SIGABRT. A signal is authoritative when the
    /// envelope carried one; exit 134 is the fallback for the families whose
    /// supervisor only sees a code.
    fn aborted(&self) -> bool {
        match self.signal {
            Some(signal) => signal == SIGABRT,
            None => self.exit_code == SIGABRT_EXIT,
        }
    }
}

/// One generation's outcome: the structured facts plus its captured streams.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GenerationFacts {
    pub facts: RunFacts,
    /// The generation's captured stdout and stderr, joined. Read ONLY by the
    /// spec-declared pattern matcher and by the signature's fallback — never by
    /// [`built_in_class`], which cannot see it.
    pub output: String,
    /// The child envelope's `result_line`: the run verb's own single most
    /// representative line of the GUEST's streams (a violation marker, its
    /// `PATINA_RESULT`, else its last non-empty stderr line). Text, so it lives
    /// here beside `output` rather than in the text-free [`RunFacts`]; read ONLY
    /// by the signature's fallback, which prefers it over the raw `output` so a
    /// supervisor diagnostic the child printed on its own stderr AFTER the guest
    /// finished (the deny-trap-armed symbol note, a trace-finalization line)
    /// cannot shadow the guest's finding. Absent without an envelope.
    pub result_line: Option<String>,
}

/// Per-guest classification rules a campaign spec declares (`classify` in the
/// spec JSON). The grep mechanism survives here, and only here: as explicit,
/// versioned, per-guest configuration rather than a string baked into patina.
///
/// Keyed by [`CampaignClass`], whose `Ord` is the severity order, so two matching
/// declarations always resolve to the more severe class — deterministically.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassifyRules {
    /// class -> output line substrings.
    pub(super) patterns: BTreeMap<CampaignClass, Vec<String>>,
    /// class -> child exit codes.
    pub(super) exit_codes: BTreeMap<CampaignClass, Vec<i32>>,
}

impl ClassifyRules {
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty() && self.exit_codes.is_empty()
    }

    /// The class this guest's declared rules assign, if any. Patterns are checked
    /// before exit codes (a matched line is more specific than a bare code), and
    /// both in severity order.
    fn declared(&self, generation: &GenerationFacts) -> Option<CampaignClass> {
        for (class, needles) in &self.patterns {
            if needles
                .iter()
                .any(|needle| generation.output.contains(needle.as_str()))
            {
                return Some(*class);
            }
        }
        for (class, codes) in &self.exit_codes {
            if codes.contains(&generation.facts.exit_code) {
                return Some(*class);
            }
        }
        None
    }
}

/// Classify one generation from its structured envelope facts plus the spec's
/// declared rules.
///
/// Envelope facts take precedence: a declared rule can only speak when the
/// structured facts reached no verdict of their own (`OK`, or the loud
/// `UNCLASSIFIED` catch-all), so a pattern can ADD a finding a level-1 guest
/// would otherwise hide but can never downgrade one patina detected.
pub fn classify(generation: &GenerationFacts, rules: &ClassifyRules) -> CampaignClass {
    let built_in = built_in_class(&generation.facts);
    if matches!(built_in, CampaignClass::Ok | CampaignClass::Unclassified)
        && let Some(declared) = rules.declared(generation)
    {
        return declared;
    }
    built_in
}

/// The class the envelope's own facts imply, with no guest output in sight.
/// Ordering encodes severity: an explicit finding wins over exit-status
/// inference, a nonzero exit is never silently OK, and anything unrecognized
/// lands LOUDLY in [`CampaignClass::Unclassified`] rather than being downgraded.
fn built_in_class(facts: &RunFacts) -> CampaignClass {
    // 1. The campaign's own wall-clock backstop killed this generation: it hung in
    //    a way neither the virtual-time watchdog nor the child's budgets caught, so
    //    the outcome is inconclusive (INFRA), never a silent OK.
    if facts.timed_out {
        return CampaignClass::Infra;
    }
    // 2. The guest was killed from OUTSIDE — SIGKILL, which it cannot deliver to
    //    itself, cannot catch, and cannot survive. The kernel OOM killer under
    //    parallel campaign load is the common source; a cgroup limit or an
    //    operator are the others. That is a host-side condition, exactly like the
    //    timeout above, and it is INFRA. Checked BEFORE every finding rule below
    //    because a killed generation ran no invariant to completion: filing it as
    //    a bug class reports a failure that does not exist, with a reproduce
    //    command that cannot reproduce it, and burns a novel-signature slot that
    //    a real bug should have had.
    if facts.host_killed() {
        return CampaignClass::Infra;
    }
    // 3. The `--starve` supervisor stall backstop. Checked before the envelope
    //    rule below because the stalled child is killed by its own supervisor,
    //    which returns this code INSTEAD of finalizing a result.
    if facts.exit_code == STARVATION_STALL_EXIT {
        return CampaignClass::StarvationStall;
    }
    // 4. No envelope at all: the child `cargo patina run` failed before it could
    //    report a result (a build failure, a pre-run gate refusal, a supervisor
    //    error). That is a harness failure, not a system-under-test finding.
    if !facts.envelope {
        return CampaignClass::Infra;
    }
    // A pre-run refusal has an envelope, but no guest executed. Preserve the
    // same infrastructure attribution as a CLI/build failure without a result.
    if facts.refusal.as_deref() == Some(crate::output::NATIVE_PRERUN_REFUSAL) {
        return CampaignClass::Infra;
    }
    // A runtime limitation is infrastructure evidence, not a guest bug. Do not
    // erase an independently reported safety verdict that preceded the stop.
    if facts.findings.iter().any(|finding| finding.known_limit)
        && facts.has_verdict("violation").is_none()
    {
        return CampaignClass::Infra;
    }
    // 5. A liveness/converge watchdog finding is its own class (a "never
    //    converges" wedge), reported by the runtime as a `runtime_findings[]`
    //    entry with `source=liveness`.
    if facts
        .findings
        .iter()
        .any(|finding| finding.source == "liveness" && !finding.known_limit)
    {
        return CampaignClass::Liveness;
    }
    // 6. A system-under-test safety violation: a `violation` verdict. Fires even
    //    on exit 0 — a violated invariant is a bug however the process exited.
    if facts.has_verdict("violation").is_some() {
        return CampaignClass::Violation;
    }
    // 7. Fault- and exploration-plane coverage failures, one class per plane so a
    //    campaign report names WHICH plane went inert. Each plane's `vacuous` bit
    //    is its own field of `fault_reports{}`, so one plane's vacuity can never
    //    be filed under another's class. Checked in a fixed order, so a generation
    //    with two vacuous planes always gets the same one class.
    for class in CampaignClass::ALL {
        if let Some(plane) = class.vacuous_plane()
            && facts.plane_vacuous(plane)
        {
            return *class;
        }
    }
    // 8. Patina fail-closed refusal: the envelope attributed the failure to
    //    patina itself. Checked after the SUT findings above, so an `always!`
    //    abort stays a VIOLATION.
    if let Some(class) = &facts.refusal {
        // A refusal the parent classified as the stall backstop keeps its own
        // class; every other refusal is the fail-closed bucket.
        if class == "starvation_stall" {
            return CampaignClass::StarvationStall;
        }
        // Patina's OWN recorder gave out at the end of the run (the trace
        // resource limit, an unwritable trace file). The shim `abort()`s after
        // it, so a guest that had already finished dies on a SIGABRT it never
        // raised — which, before this, was reported as `guest_abort
        // unattributed`: a bug filed against the system under test for a failure
        // inside patina, whose printed reproduce command could not reproduce it
        // (the abort needs the `--record` the reproduce command omitted). It is
        // INFRA for the same reason a timeout is: the harness, not a result.
        //
        // A failed trace CHANNEL (the scratch file vanished, its directory did,
        // the filesystem refused) is the same bargain reached a different way:
        // the guest ran, its verdict is whatever it reached, and only the
        // artifact is lost. One difference — a guest that failed here may well
        // have ABORTED, since nothing about a channel failure skips the guest's
        // own death — so rather than naming a class outright, a guest that
        // failed falls THROUGH to the rules below, which read the exit status
        // and signal that are still its own.
        if class == TRACE_UNAVAILABLE_CLASS {
            match facts.refusal_guest_exit_code {
                None | Some(0) => return CampaignClass::Infra,
                Some(_) => {}
            }
        } else if class == SHUTDOWN_FAILURE_CLASS {
            // ...but ONLY when the guest itself came through clean. The trace
            // budget is spent by LONG runs, which are precisely the runs most
            // likely to have found something; a generation that both failed for
            // a real reason and broke the recorder must be filed under the
            // GUEST's failure, or the finding vanishes into an infra bucket. The
            // shim records the status the guest reached before the atexit abort
            // replaced it (`refusal.guest_exit_code`), so the two cases are
            // distinguishable here. The unusable trace does not stop being true
            // — the report still says so — it just stops being the headline.
            //
            // An unrecorded status (`None`) keeps the INFRA demotion: with no
            // evidence the guest failed, patina's own recorder is the only thing
            // known to have gone wrong.
            match facts.refusal_guest_exit_code {
                None | Some(0) => return CampaignClass::Infra,
                // The guest's own class. It cannot have aborted (an `abort()`
                // skips atexit and never reaches finalization), so what is left
                // is a panic or a deliberate nonzero exit: rule 11's bucket,
                // reached directly because `exit_code`/`signal` here describe
                // patina's abort and would otherwise misfile it as GUEST_ABORT.
                Some(_) => return CampaignClass::Unclassified,
            }
        } else {
            return CampaignClass::FailClosedAbort;
        }
    }
    // 9. An abort patina did NOT attribute to itself is the guest's own doing.
    //    This is §4.4's inversion: before the envelope carried `refusal`, every
    //    unattributed SIGABRT was blamed on patina and buried in an infra-looking
    //    bucket; now it is a finding in its own right.
    if facts.aborted() {
        return CampaignClass::GuestAbort;
    }
    // 10. A clean exit with no finding is OK.
    if facts.exit_code == 0 {
        return CampaignClass::Ok;
    }
    // 11. A nonzero exit that matched no class above is UNCLASSIFIED — surfaced
    //    loudly for triage, never silently dropped as OK or mislabeled. A guest
    //    that fails in a way patina cannot see structurally declares a
    //    `classify` rule for it in its campaign spec (arc §4.3).
    CampaignClass::Unclassified
}

/// The distinct exit code the native supervisor returns for a `--starve` stall,
/// mirrored here for the classifier (kept in sync with `lib.rs`).
pub(super) const STARVATION_STALL_EXIT: i32 = 111;

/// Build a signature from a classified generation.
///
/// The shape comes from the same structured facts the class did, so two
/// generations that hit the same invariant dedup to one signature regardless of
/// how the guest worded its output. Only when the facts carry nothing for the
/// class (`UNCLASSIFIED`, `INFRA`, a declared-pattern class) does it fall back to
/// the captured output, which is all there is in those cases.
pub fn signature(class: CampaignClass, generation: &GenerationFacts) -> Signature {
    let shape = normalize_shape(&primary_finding(class, generation));
    let policy = policy_annotation(&generation.output);
    Signature {
        class,
        shape,
        policy,
    }
}

/// The most representative description of the finding for the class, from the
/// structured facts where they carry one.
fn primary_finding(class: CampaignClass, generation: &GenerationFacts) -> String {
    let shape = primary_finding_shape(class, generation);
    // A generation whose class came from the GUEST while patina's own recorder
    // also gave out is reproducible only up to a point: the finding stands, but
    // the trace it would be replayed from was never written. Say so on the shape
    // itself — it is the line triage reads — rather than let a printed
    // `reproduce` command promise an artifact that is not there. INFRA already
    // names the refusal in its own shape and does not need the suffix.
    if class != CampaignClass::Infra
        && matches!(
            generation.facts.refusal.as_deref(),
            Some(SHUTDOWN_FAILURE_CLASS | TRACE_UNAVAILABLE_CLASS)
        )
    {
        return format!("{shape} trace=unusable");
    }
    shape
}

/// The class's own most representative description, before any cross-cutting
/// annotation [`primary_finding`] adds.
fn primary_finding_shape(class: CampaignClass, generation: &GenerationFacts) -> String {
    let facts = &generation.facts;
    let structured = match class {
        CampaignClass::Liveness => facts
            .has_finding("liveness")
            .map(|finding| format!("liveness kind={}", finding.kind)),
        CampaignClass::Violation => facts
            .has_verdict("violation")
            .map(|verdict| format!("verdict kind=violation label={}", verdict.label)),
        // An abort patina did not attribute to itself and the guest never
        // claimed with an `abort_intent` verdict. `unattributed` is the honest
        // head — nothing structured says WHY — but it must not be the whole
        // shape: on a guest with no cooperative SDK (the common case) every
        // distinct abort in a campaign then dedups into ONE useless signature.
        // Recover what the streams do carry, so two different aborts stay two
        // findings and each names its own cause.
        CampaignClass::GuestAbort => Some(match facts.has_verdict("abort_intent") {
            Some(verdict) => format!("guest_abort label={}", verdict.label),
            None => match death_attribution(generation) {
                Some(evidence) => format!("guest_abort unattributed {evidence}"),
                None => "guest_abort unattributed".to_string(),
            },
        }),
        CampaignClass::FailClosedAbort => facts
            .refusal
            .as_ref()
            .map(|class| format!("refusal class={class}")),
        CampaignClass::StarvationStall => Some("starvation stall".to_string()),
        // A host-side kill has ONE shape, always: there is no finding in it to
        // describe, and every such generation must dedup onto the same entry
        // rather than spraying novel signatures made of whatever the guest
        // happened to have printed when the kernel took it away.
        // (A generation the campaign's own backstop killed is host-killed too,
        // but it keeps the timeout marker as its shape: WHY it was killed is the
        // finding there, and the backstop already said so.)
        CampaignClass::Infra if facts.host_killed() && !facts.timed_out => {
            Some(HOST_KILL_SHAPE.to_string())
        }
        // An INFRA generation patina attributed to ITSELF (the recorder giving
        // out) is named by that attribution rather than by whatever text trailed
        // the run — the raw `PATINA_INFRA native_run ...` line carries per-run
        // paths and a pid, which fragment the signature.
        CampaignClass::Infra => facts
            .refusal
            .as_ref()
            .map(|class| format!("refusal class={class}")),
        // A hardware/OS fault: the guest died executing bad code without ever
        // reaching `abort()`. Name the signal — it is the whole finding — and
        // keep the guest's last words after it for triage.
        // A vacuous plane is a fact about THIS class and keeps precedence; a
        // fault signal is the fallback for the classes that carry no fact.
        _ => class
            .vacuous_plane()
            .map(|plane| format!("vacuous plane={plane}"))
            .or_else(|| {
                facts
                    .fault_signal()
                    .map(|signal| match death_attribution(generation) {
                        Some(evidence) => format!("guest_fault signal={signal} {evidence}"),
                        None => format!("guest_fault signal={signal}"),
                    })
            }),
    };
    if let Some(shape) = structured {
        return shape;
    }
    // No structured fact for this class. The run verb's own summary of the
    // GUEST's streams comes first: it was computed from those streams alone, so
    // a supervisor diagnostic appended after them on the child's own stderr
    // cannot become the shape. Without an envelope (a build failure, a pre-run
    // refusal, a timeout kill) the captured output is all there is.
    //
    // Either source can still land on a RUNTIME DIAGNOSTIC — patina's own
    // end-of-run summaries print on the GUEST's stderr, after the guest's last
    // word, so they are inside the streams the run verb summarized as well as at
    // the tail of the captured output. Both paths therefore filter through
    // [`is_runtime_diagnostic`] and keep walking backwards to the guest's own
    // last meaningful line.
    if let Some(line) = generation
        .result_line
        .as_deref()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !is_runtime_diagnostic(line))
    {
        return line.to_string();
    }
    let mut lines = generation
        .output
        .lines()
        .map(str::trim)
        .rev()
        .filter(|line| !line.is_empty());
    let mut last_nonempty = None;
    for line in &mut lines {
        last_nonempty.get_or_insert(line);
        if !is_runtime_diagnostic(line) {
            return line.to_string();
        }
    }
    // Every line was a diagnostic: a shape with no evidence in it still beats an
    // empty shape, which would collapse unrelated failures into one signature.
    last_nonempty.unwrap_or_default().to_string()
}

/// Whether `line` is patina's OWN diagnostic — a summary, a progress marker, or
/// a pre-run advisory the runtime or the supervisor printed — rather than
/// evidence of the failure.
///
/// The principle: only the guest's own output is a failure's shape. Patina's
/// diagnostics bracket the run instead of describing it, and they carry
/// per-generation numbers (`sites_activated=33` vs `35`, per-site `e<N>` edge
/// counts, a binary path) that no numeric normalizer can collapse. Letting one
/// become the shape makes every repeat of the SAME failure look NOVEL and
/// defeats dedup — the single most valuable thing a long campaign does. It is
/// the deeper form of the bug the `result-line-beats-supervisor-note` selftest
/// already guards: there the diagnostic rode the CHILD's stderr, here it rides
/// the guest's own.
///
/// Two tiers, because they reach the tail of the captured output two different
/// ways:
///
/// 1. **Runtime end-of-run reports**, printed by the runtime INSIDE the guest
///    process, after the guest's last word. Matched by SHAPE — a `PATINA_`
///    prefix with a `_REPORT` suffix — so a report added later needs no change
///    here. That is `patina_runtime::Report`, one variant per suppression knob:
///    `PATINA_SCHEDULE_REPORT`, `PATINA_SWARM_REPORT`, `PATINA_LIVENESS_REPORT`,
///    `PATINA_SDK_REPORT`, `PATINA_FS_FAULT_REPORT`, `PATINA_DNS_FAULT_REPORT`,
///    `PATINA_NET_FAULT_REPORT`, `PATINA_ENTROPY_FAULT_REPORT`,
///    `PATINA_CLOCK_FAULT_REPORT`, `PATINA_CUSTOMOP_FAULT_REPORT`,
///    `PATINA_COVERAGE_REPORT`, `PATINA_DEPTH_REPORT`. Three siblings are named
///    outright because their line name is not their knob name:
///    `PATINA_SCHEDULE_POLICY` (knob `PATINA_SCHEDULE_POLICY_REPORT`) and the
///    `PATINA_LIFECYCLE` / `PATINA_LIFECYCLE_EVENT` progress markers.
///
/// 2. **Supervisor pre-run advisories**, printed by the child `cargo patina run`
///    BEFORE the guest was launched. They surface at the *tail* only because the
///    campaign appends the child's own stderr after the guest's streams (two
///    pipes, no recoverable interleaving), so chronology cannot separate them
///    and this predicate must.
///
/// Deliberately NOT skipped, which is why this is a narrow rule and not a
/// blanket `patina:` prefix: most `patina: ...` lines are fail-closed REFUSALS
/// ("… is not modeled; failing closed", "step budget … exhausted", "always!
/// invariant violated", "the deterministic runtime failed to initialize"). Those
/// ARE the cause of death, and `REFUSAL_CLASSES` in `output.rs` recognizes only
/// some of them structurally — the rest reach a signature exactly through this
/// fallback. Likewise kept: `PATINA_RESULT`, `PATINA_VIOLATION`,
/// `PATINA_VERDICT`, `PATINA_INFRA`, the `PATINA_BUGGIFY_*` misuse markers, the
/// `cargo-patina: ...` CLI errors, and the campaign's own
/// `patina: campaign generation exceeded timeout_secs=` marker.
pub(super) fn is_runtime_diagnostic(line: &str) -> bool {
    let line = line.trim_start();
    let head = line.split_whitespace().next().unwrap_or_default();
    // Tier 1: the runtime's end-of-run report family.
    if let Some(name) = head.strip_prefix("PATINA_")
        && (name.ends_with("_REPORT")
            || matches!(name, "SCHEDULE_POLICY" | "LIFECYCLE" | "LIFECYCLE_EVENT"))
    {
        return true;
    }
    // Tier 2: the supervisor's pre-run advisories.
    //
    // * `note: N linked symbol(s) are deny-trap armed under patina …` — the
    //   "fails later" note. Every `note:` line is an aside by construction (the
    //   panic runtime's `note: run with RUST_BACKTRACE=1` too), never a finding.
    // * `patina: WARNING: running <bin> with N UNSUPPORTED symbol(s) …` and its
    //   closing paragraph `patina: these host symbols are NOT interposed …`,
    //   with the per-symbol rows between them printed as `patina:   <symbol>` /
    //   `patina:     provenance=…` — indented continuations of the block, which
    //   is how they are recognized (and how a future block's rows will be).
    // * `patina: N direct-syscall instruction site(s) … are SUD-managed` and the
    //   timestamp-counter twin: both spelled `… instruction site(s) …`.
    if line.starts_with("note:") {
        return true;
    }
    match line.strip_prefix("patina:") {
        Some(rest) => {
            rest.trim().is_empty()
                || rest.starts_with("  ")
                || rest.trim_start().starts_with("WARNING:")
                || rest.starts_with(" these host symbols are NOT interposed")
                || rest.contains(" instruction site(s) ")
        }
        None => false,
    }
}

/// A death patina could NOT attribute structurally — an abort with no
/// `abort_intent` verdict and no refusal, or a fault signal — can still be read
/// off the guest's own streams: the most specific evidence of WHY it died.
///
/// Investigated and rejected as sources, for the record:
///   * `abort_intent` — the cooperative SDK verdict. This function is reached
///     only when the guest never emitted one, which is every guest that does not
///     link the patina SDK.
///   * `refusal` — patina's own fail-closed attribution. Reached only when it is
///     absent too; when present the generation is a `FAIL_CLOSED_ABORT` instead.
///   * the shim's `LAST_BOUNDARY_SYMBOL` — the name of the interposed symbol
///     entering the boundary. It exists (`patina-native-shim`), but it is a
///     best-effort in-process diagnostic that the shim prints only on ITS OWN
///     pre-init/deny-trap abort paths — and those already print a `patina: ...`
///     line, which arrives here as evidence anyway. Exporting it for a guest's
///     abort would mean writing it out of a signal-time path in
///     `c/patina_posix.c`, which is not clean.
///
/// So: a Rust panic, which is how an ordinary guest reaches `SIGABRT` (a panic
/// that cannot unwind, a double panic, `panic=abort`). Its header carries the
/// aborting THREAD and the SITE, and the message is on the next line — both
/// halves are needed, since `called \`Result::unwrap()\` on an \`Err\` value` is
/// identical across unrelated sites. Failing that, the guest's own last
/// meaningful line, which is also where patina's own abort diagnostics land
/// (`patina: ... failing closed`, `PATINA_INFRA native_run signal=6 ...`) —
/// deliberately NOT filtered as diagnostics, because for an abort they ARE the
/// attribution.
fn death_attribution(generation: &GenerationFacts) -> Option<String> {
    let lines: Vec<&str> = generation.output.lines().map(str::trim).collect();
    // The LAST panic wins: a double panic aborts on its second, and the abort is
    // what this shape explains.
    if let Some(at) = lines
        .iter()
        .rposition(|line| line.starts_with("thread '") && line.contains("panicked at "))
    {
        let header = lines[at];
        let thread = header
            .strip_prefix("thread '")
            .and_then(|rest| rest.split_once('\''))
            .map(|(name, _)| name)
            .unwrap_or("?");
        let site = header
            .split_once("panicked at ")
            .map(|(_, site)| site.trim_end_matches(':'))
            .unwrap_or_default();
        let message = lines[at + 1..]
            .iter()
            .find(|line| !line.is_empty() && !is_runtime_diagnostic(line))
            .copied()
            .unwrap_or_default();
        return Some(
            format!("panic thread={thread} at={site} msg={message}")
                .trim()
                .to_string(),
        );
    }
    lines
        .iter()
        .rev()
        .find(|line| !line.is_empty() && !is_runtime_diagnostic(line))
        .map(|line| line.to_string())
}

/// Collapse run-specific values (digit and hex runs) so a signature captures the
/// *shape* of a finding, not its exact numbers — `elapsed_nanos=400` and
/// `elapsed_nanos=920` share one signature.
fn normalize_shape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            // Collapse a maximal run of ASCII digits to a single '#'.
            out.push('#');
            while chars.peek().is_some_and(|n| n.is_ascii_digit()) {
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Extract the exploration-policy bug-depth annotation, if the run emitted one, so
/// two failures found at different interleaving depths are distinguished. A
/// signature *annotation*, never a class: the depth is a property of how the
/// failure was reached, and the `PATINA_SCHEDULE_POLICY` line is the only place
/// it is reported.
fn policy_annotation(output: &str) -> String {
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("PATINA_SCHEDULE_POLICY")
            && let Some(depth) = line
                .split_whitespace()
                .find_map(|token| token.strip_prefix("bug_depth="))
        {
            return format!("bug_depth={depth}");
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::super::selftest::{declared_rules_fixture, planted};
    use super::super::vacuity_class;
    use super::*;
    use patina_dst_runtime::FaultKnob;

    /// Every class token round-trips, and [`CampaignClass::ALL`] is complete and
    /// in the declaration (severity) order [`ClassifyRules`] relies on.
    #[test]
    fn every_class_round_trips_its_token() {
        for class in CampaignClass::ALL {
            assert_eq!(CampaignClass::parse(class.as_str()), Some(*class));
        }
        let mut sorted = CampaignClass::ALL.to_vec();
        sorted.sort();
        assert_eq!(
            sorted,
            CampaignClass::ALL.to_vec(),
            "CampaignClass::ALL must be in `Ord` (severity) order"
        );
        assert_eq!(CampaignClass::parse("NOT_A_CLASS"), None);
    }

    #[test]
    fn every_class_is_reachable_from_structured_facts() {
        let rules = ClassifyRules::default();
        let fired: Vec<CampaignClass> = vec![
            classify(&planted(RunFacts::ok(), ""), &rules),
            classify(
                &planted(RunFacts::ok().verdict("violation", "x"), ""),
                &rules,
            ),
            classify(
                &planted(RunFacts::ok().finding("liveness", "no_progress"), ""),
                &rules,
            ),
            classify(&planted(RunFacts::ok().vacuous("fs"), ""), &rules),
            classify(&planted(RunFacts::ok().vacuous("dns"), ""), &rules),
            classify(&planted(RunFacts::ok().vacuous("net"), ""), &rules),
            classify(&planted(RunFacts::ok().vacuous("entropy"), ""), &rules),
            classify(&planted(RunFacts::ok().vacuous("clock"), ""), &rules),
            classify(&planted(RunFacts::ok().vacuous("custom_op"), ""), &rules),
            classify(&planted(RunFacts::ok().vacuous("swarm"), ""), &rules),
            classify(
                &planted(RunFacts::ok().exit(SIGABRT_EXIT).signal(SIGABRT), ""),
                &rules,
            ),
            classify(
                &planted(
                    RunFacts::ok()
                        .exit(SIGABRT_EXIT)
                        .signal(SIGABRT)
                        .refusal("shim_fatal"),
                    "",
                ),
                &rules,
            ),
            classify(
                &planted(RunFacts::ok().exit(STARVATION_STALL_EXIT).no_envelope(), ""),
                &rules,
            ),
            classify(&planted(RunFacts::ok().timed_out(), ""), &rules),
            classify(&planted(RunFacts::ok().exit(3), ""), &rules),
        ];
        assert_eq!(fired, CampaignClass::ALL.to_vec());
    }

    /// The structural half of the guest-agnostic doctrine: no built-in class may
    /// be decided by guest output. `built_in_class` takes [`RunFacts`], which has
    /// no text in it at all, so the same facts classify identically whatever the
    /// guest printed.
    #[test]
    fn guest_output_alone_never_changes_a_built_in_class() {
        let rules = ClassifyRules::default();
        let noisy = "GUEST_VIOLATION two-leaders\nGUEST_BUG reordered\npanicked at src/x.rs:9\nPATINA_FS_FAULT_REPORT vacuous=1";
        for facts in [
            RunFacts::ok(),
            RunFacts::ok().exit(3),
            RunFacts::ok().exit(SIGABRT_EXIT).signal(SIGABRT),
        ] {
            assert_eq!(
                classify(&planted(facts.clone(), noisy), &rules),
                classify(&planted(facts, ""), &rules),
            );
        }
    }

    #[test]
    fn declared_rules_add_findings_but_never_downgrade_one() {
        let rules = declared_rules_fixture();
        // A level-1 guest's own text, with zero guest modification.
        assert_eq!(
            classify(&planted(RunFacts::ok(), "checksum mismatch"), &rules),
            CampaignClass::Violation
        );
        assert_eq!(
            classify(&planted(RunFacts::ok().exit(3), ""), &rules),
            CampaignClass::Violation
        );
        // The same text with no rule declared stays OK: the rule classifies, not
        // the string.
        assert_eq!(
            classify(
                &planted(RunFacts::ok(), "checksum mismatch"),
                &ClassifyRules::default()
            ),
            CampaignClass::Ok
        );
        // An envelope finding always wins over a declared rule.
        assert_eq!(
            classify(
                &planted(
                    RunFacts::ok().exit(3).refusal("fingerprint_mismatch"),
                    "checksum mismatch"
                ),
                &rules
            ),
            CampaignClass::FailClosedAbort
        );
    }

    /// A knob whose vacuity has an outcome class must have a report to read it
    /// off, that class must name a `fault_reports{}` plane, and a run whose plane
    /// reports `vacuous` must actually classify as it. The network fault-plane
    /// gap this test used to pin — a report with no class, silently classifying
    /// `OK` — is now closed: every knob with a report has a matching class, which
    /// is what the `Some` branch below proves for each of them.
    #[test]
    fn vacuity_classes_match_the_classifier() {
        let rules = ClassifyRules::default();
        let mut with_report = 0;
        for knob in FaultKnob::ALL {
            let class = vacuity_class(*knob);
            if knob.meta().report.is_none() {
                assert_eq!(
                    class, None,
                    "{knob:?} has a vacuity class but no report to read it off"
                );
                continue;
            };
            with_report += 1;
            let expected = class.unwrap_or_else(|| {
                panic!("{knob:?} has a report but no vacuity_class — give it one, or its class")
            });
            let plane = expected.vacuous_plane().unwrap_or_else(|| {
                panic!("{expected:?} is a vacuity class with no fault_reports plane to read")
            });
            let actual = classify(&planted(RunFacts::ok().vacuous(plane), ""), &rules);
            assert_eq!(
                actual, expected,
                "{knob:?} declares {expected:?} but a vacuous {plane:?} plane classifies as {actual:?}"
            );
        }
        assert!(
            with_report > 0,
            "this gate proves nothing unless some knob has a report to read"
        );
    }
}
