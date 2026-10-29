//! Structured outcome classification and failure signatures.

use super::Signature;
use super::generation::SIGKILL;
use super::state::json_required_str;
use std::collections::BTreeMap;

// ===========================================================================
// Classifier (pure) + signatures
// ===========================================================================

/// The per-generation outcome classes: `OK`, then the failure classes in
/// descending severity. An explicit finding is never downgraded, and a nonzero
/// exit is never silently OK.
///
/// The declaration order is the severity order: [`ClassifyRules`] iterates its
/// declared classes through it, so two matching declarations always resolve to
/// the more severe one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CampaignClass {
    /// The run completed clean (exit 0, no finding).
    Ok,
    /// Running the generation again did not reproduce it: the campaign ran a
    /// novel finding's reproduce path, or a sampled clean generation a second
    /// time, and the class, signature, verdicts or trace digest differed. The
    /// only cross-run class — [`classify`] never returns it, reproduction
    /// verification does — and the most severe failure, because every other
    /// class's reproduce command rests on the run being deterministic. The
    /// observed outcome and the reproduction both travel with it.
    Nondeterminism,
    /// A system-under-test safety/assertion violation: a `VerdictKind::Violation`
    /// the guest reported through the verdict ABI (which `always!` lowers to), or
    /// a class a campaign spec declared for this guest ([`ClassifyRules`]).
    Violation,
    /// A liveness-watchdog violation: a `runtime_findings[]` entry with
    /// `source=liveness` — a virtual-time no-progress wedge.
    Liveness,
    /// A fault or exploration plane went inert: a configured fault class saw
    /// eligible work often enough to have fired several times over yet applied
    /// zero effects, a custom-op knob reached no eligible operation, or a swarm
    /// draw had nothing to select. The plane names come from the run's
    /// `fault_reports{}` and travel in the signature. A coverage failure, not a
    /// SUT finding.
    Vacuous,
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
    /// Every class, in severity order. The compiler holds it complete: see
    /// the exhaustive match below the `impl`.
    pub const ALL: &'static [CampaignClass] = &[
        CampaignClass::Ok,
        CampaignClass::Nondeterminism,
        CampaignClass::Violation,
        CampaignClass::Liveness,
        CampaignClass::Vacuous,
        CampaignClass::GuestAbort,
        CampaignClass::FailClosedAbort,
        CampaignClass::Infra,
        CampaignClass::Unclassified,
    ];

    pub const fn as_str(&self) -> &'static str {
        match self {
            CampaignClass::Ok => "OK",
            CampaignClass::Nondeterminism => "NONDETERMINISM",
            CampaignClass::Violation => "VIOLATION",
            CampaignClass::Liveness => "LIVENESS",
            CampaignClass::Vacuous => "VACUOUS",
            CampaignClass::GuestAbort => "GUEST_ABORT",
            CampaignClass::FailClosedAbort => "FAIL_CLOSED_ABORT",
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

    /// Whether only comparing two runs of a generation can reach this class, so
    /// no single run's facts — and no spec-declared rule — can.
    pub const fn is_cross_run(&self) -> bool {
        matches!(self, CampaignClass::Nondeterminism)
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
    pub const fn is_finding(&self) -> bool {
        self.is_failure() && !matches!(self, CampaignClass::Infra)
    }
}

// `CampaignClass::ALL` is complete by construction. The match has no
// wildcard, so a variant added to the enum does not compile until it is given
// a place here, its index in `ALL`; the loop then holds every entry of `ALL`
// to its place and to declaration (severity) order.
const _: () = {
    const fn place(class: CampaignClass) -> usize {
        match class {
            CampaignClass::Ok => 0,
            CampaignClass::Nondeterminism => 1,
            CampaignClass::Violation => 2,
            CampaignClass::Liveness => 3,
            CampaignClass::Vacuous => 4,
            CampaignClass::GuestAbort => 5,
            CampaignClass::FailClosedAbort => 6,
            CampaignClass::Infra => 7,
            CampaignClass::Unclassified => 8,
        }
    }
    let all = CampaignClass::ALL;
    let mut index = 0;
    while index < all.len() {
        assert!(place(all[index]) == index && all[index] as usize == index);
        index += 1;
    }
};

/// The `fault_reports{}` planes whose `vacuous` bit is a coverage failure. The
/// schedule plane is not one: its vacuity is a runtime finding of its own.
pub(super) const VACUITY_PLANES: &[&str] =
    &["fs", "dns", "net", "entropy", "clock", "custom_op", "swarm"];

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
/// The refusal class for a run whose crash patina could not carry out
/// (recovery, snapshot export or the handoff failed). Patina's own limit,
/// never a result about the guest.
pub(super) const CRASH_FAILED_CLASS: &str = "crash_failed";
/// The refusal class for a run the host could not give what the virtual
/// process granted (a stack limit past the host's hard limit). An operational
/// condition of the host, like a timeout: never a result about the guest.
pub(super) const HOST_LIMIT_CLASS: &str = "host_limit";

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
    /// `guest_exit.code` — the status the guest itself exited with, which the
    /// supervisor's own process status need not repeat.
    pub guest_exit_code: Option<i32>,
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
    /// `replay_divergence` — a `replay` that ran but did not follow its trace
    /// (an operation past its end, a mismatched operation or outcome, recorded
    /// operations left over), as the runtime reported it on the facts channel;
    /// or a crash-restart replay that departed from its recording at the crash,
    /// as the supervisor reports it (`crash_restart.terminal_outcome.kind`).
    /// Classification does not read it: only the replays of a generation's own
    /// trace, reproduction verification and `minimize`'s oracle, do.
    pub replay_diverged: bool,
    /// `verdicts[]`, in call order.
    pub verdicts: Vec<VerdictFacts>,
    /// The `fault_reports{}` planes whose `vacuous` bit is set.
    pub vacuous_planes: Vec<String>,
    /// `runtime_findings[]`.
    pub findings: Vec<FindingFacts>,
}

impl RunFacts {
    /// The run's exit facts as one comparable string: the process's code, the
    /// guest's full code, the signal, and patina's refusal class with the
    /// status the guest reached under it.
    pub(crate) fn exit_status(&self) -> String {
        let mut exit = format!("exit={}", self.exit_code);
        if let Some(code) = self.guest_exit_code {
            exit.push_str(&format!(" guest_exit={code}"));
        }
        if let Some(signal) = self.signal {
            exit.push_str(&format!(" signal={signal}"));
        }
        if let Some(refusal) = &self.refusal {
            exit.push_str(&format!(" refusal={refusal}"));
        }
        if let Some(code) = self.refusal_guest_exit_code {
            exit.push_str(&format!(" refusal_guest_exit={code}"));
        }
        exit
    }

    fn has_verdict(&self, kind: &str) -> Option<&VerdictFacts> {
        self.verdicts.iter().find(|verdict| verdict.kind == kind)
    }

    fn has_finding(&self, source: &str) -> Option<&FindingFacts> {
        self.findings
            .iter()
            .find(|finding| finding.source == source)
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
    /// The envelope's `verdicts[]` rows exactly as reported, sequence and detail
    /// included, one JSON object each. Read ONLY by reproduction verification:
    /// [`VerdictFacts`] drops `detail` because it varies between generations,
    /// but two runs of ONE generation must agree on it.
    pub exact_verdicts: Vec<String>,
    /// The envelope's `schedule_policy.bug_depth`: how many live ordering
    /// decisions the exploration policy made in this schedule. A signature
    /// annotation, never a class input.
    pub bug_depth: Option<u64>,
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
    // 3. No envelope at all: the child `cargo patina run` failed before it could
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
    // 4. A liveness/converge watchdog finding is its own class (a "never
    //    converges" wedge), reported by the runtime as a `runtime_findings[]`
    //    entry with `source=liveness`.
    if facts
        .findings
        .iter()
        .any(|finding| finding.source == "liveness" && !finding.known_limit)
    {
        return CampaignClass::Liveness;
    }
    // 5. A system-under-test safety violation: a `violation` verdict. Fires even
    //    on exit 0 — a violated invariant is a bug however the process exited.
    if facts.has_verdict("violation").is_some() {
        return CampaignClass::Violation;
    }
    // 6. Patina fail-closed refusal: the envelope attributed the failure to
    //    patina itself. Checked after the SUT findings above, so an `always!`
    //    abort stays a VIOLATION.
    if let Some(class) = &facts.refusal {
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
        // A crash patina could not carry out stopped the guest before it
        // could reach a verdict of its own: the harness failing, like a
        // timeout.
        if class == CRASH_FAILED_CLASS || class == HOST_LIMIT_CLASS {
            return CampaignClass::Infra;
        }
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
                // is a panic or a deliberate nonzero exit: rule 9's bucket,
                // reached directly because `exit_code`/`signal` here describe
                // patina's abort and would otherwise misfile it as GUEST_ABORT.
                Some(_) => return CampaignClass::Unclassified,
            }
        } else {
            return CampaignClass::FailClosedAbort;
        }
    }
    // 7. An abort patina did NOT attribute to itself is the guest's own doing.
    //    This is §4.4's inversion: before the envelope carried `refusal`, every
    //    unattributed SIGABRT was blamed on patina and buried in an infra-looking
    //    bucket; now it is a finding in its own right.
    if facts.aborted() {
        return CampaignClass::GuestAbort;
    }
    // 8. A clean exit with no finding is OK, unless a fault or exploration plane
    //    went inert: then it is a coverage failure, and the signature names the
    //    planes. Vacuity is judged only here, on a run that otherwise passed: a
    //    run that failed on its own (every rule above, and the nonzero exit
    //    below) keeps that failure as its headline, exactly as it would without
    //    the fault knobs that went inert.
    if facts.exit_code == 0 {
        if facts.vacuous_planes.is_empty() {
            return CampaignClass::Ok;
        }
        return CampaignClass::Vacuous;
    }
    // 9. A nonzero exit that matched no class above is UNCLASSIFIED — surfaced
    //    loudly for triage, never silently dropped as OK or mislabeled. A guest
    //    that fails in a way patina cannot see structurally declares a
    //    `classify` rule for it in its campaign spec (arc §4.3).
    CampaignClass::Unclassified
}

/// Build a signature from a classified generation.
///
/// The shape comes from the same structured facts the class did, so two
/// generations that hit the same invariant dedup to one signature regardless of
/// how the guest worded its output. Only when the facts carry nothing for the
/// class (`UNCLASSIFIED`, `INFRA`, a declared-pattern class) does it fall back to
/// the captured output, which is all there is in those cases.
pub fn signature(class: CampaignClass, generation: &GenerationFacts) -> Signature {
    let shape = normalize_shape(&primary_finding(class, generation));
    let policy = generation
        .bug_depth
        .map(|depth| format!("bug_depth={depth}"))
        .unwrap_or_default();
    Signature {
        class,
        shape,
        policy,
    }
}

/// The most representative description of the finding for the class, from the
/// structured facts where they carry one: the exact line a signature's shape is
/// cut from, before [`normalize_shape`] collapses its numbers. Reproduction
/// verification compares it exactly, since a number that varies between two
/// runs of one generation is the leak the shape hides.
pub(super) fn primary_finding(class: CampaignClass, generation: &GenerationFacts) -> String {
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
        // The inert planes are the whole finding, in a fixed order so two
        // generations with the same planes share a signature.
        CampaignClass::Vacuous => {
            let mut planes = facts.vacuous_planes.clone();
            planes.sort();
            Some(format!("vacuous planes={}", planes.join(",")))
        }
        // A fault signal is the fallback for the classes that carry no fact.
        _ => facts
            .fault_signal()
            .map(|signal| match death_attribution(generation) {
                Some(evidence) => format!("guest_fault signal={signal} {evidence}"),
                None => format!("guest_fault signal={signal}"),
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
        return marker_evidence(line);
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
            return marker_evidence(line);
        }
    }
    // Every line was a diagnostic: a shape with no evidence in it still beats an
    // empty shape, which would collapse unrelated failures into one signature.
    marker_evidence(last_nonempty.unwrap_or_default())
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
///    `PATINA_COVERAGE_REPORT`. Three siblings are named
///    outright because their line name is not their knob name:
///    `PATINA_SCHEDULE_POLICY` (knob `PATINA_SCHEDULE_POLICY_REPORT`) and the
///    `PATINA_LIFECYCLE` / `PATINA_LIFECYCLE_EVENT` progress markers, and the
///    crash-restart supervisor's `PATINA_CRASH_RESTART` summary, which names
///    both incarnations' host pids.
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
            || matches!(
                name,
                "SCHEDULE_POLICY" | "LIFECYCLE" | "LIFECYCLE_EVENT" | "CRASH_RESTART"
            ))
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
///     the staged `patina_posix.c`, which is not clean.
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
        .map(|line| marker_evidence(line))
}

/// A line as finding evidence: the line itself, except that the native
/// supervisor's `PATINA_INFRA native_run` line loses its trace fields.
///
/// The supervisor writes `trace=incomplete trace_path="…" reason="…"` when the
/// trace could not be finalized (`append_native_infra_marker`): the path is
/// the generation's own trace, and the reason names its random scratch file.
/// Kept, they make one deterministic fault read differently on every run and
/// under every reproduction: a novel signature each generation, and a false
/// nondeterminism finding. `trace=incomplete` and the signal stay.
fn marker_evidence(line: &str) -> String {
    let line = line.trim();
    if line.starts_with("PATINA_INFRA native_run ") {
        return line
            .split_once(" trace_path=")
            .map_or(line, |(stable, _)| stable)
            .to_string();
    }
    line.to_string()
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

#[cfg(test)]
mod tests {
    use super::super::selftest::{declared_rules_fixture, planted};
    use super::super::vacuity_plane;
    use super::*;
    use patina_dst_runtime::FaultKnob;

    /// A stack limit the host could not apply, or a crash patina could not
    /// carry out, ends the guest at the host's hand: INFRA, never a finding.
    #[test]
    fn a_host_side_failure_is_infra() {
        for generation in [
            planted(
                RunFacts::ok().exit(134).signal(6).refusal(HOST_LIMIT_CLASS),
                "PATINA_INFRA host_limit reason=\"setrlimit(RLIMIT_STACK)\"\n",
            ),
            planted(
                RunFacts::ok().exit(113).refusal(CRASH_FAILED_CLASS),
                "PATINA_INFRA crash_failed reason=\"export failed\"\n",
            ),
        ] {
            let class = classify(&generation, &ClassifyRules::default());
            assert_eq!(class, CampaignClass::Infra);
            assert!(!class.is_finding());
        }
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
            classify(&planted(RunFacts::ok().timed_out(), ""), &rules),
            classify(&planted(RunFacts::ok().exit(3), ""), &rules),
        ];
        // The cross-run class is reached by comparing two runs, never from one
        // run's facts; the selftest proves it fires through the comparison.
        let single_run: Vec<CampaignClass> = CampaignClass::ALL
            .iter()
            .copied()
            .filter(|class| !class.is_cross_run())
            .collect();
        assert_eq!(fired, single_run);
        // Every class token round-trips (ALL's order is checked at compile time).
        for class in CampaignClass::ALL {
            assert_eq!(CampaignClass::parse(class.as_str()), Some(*class));
        }
        assert_eq!(CampaignClass::parse("NOT_A_CLASS"), None);
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

    /// A knob that reports vacuity must name the `fault_reports{}` plane it
    /// reports under, and a run whose plane reports `vacuous` must classify
    /// `VACUOUS` with that plane in its signature; a knob with no report names
    /// no plane.
    #[test]
    fn vacuity_planes_match_the_classifier() {
        let rules = ClassifyRules::default();
        let mut with_report = 0;
        for knob in FaultKnob::ALL {
            let plane = vacuity_plane(*knob);
            if knob.meta().report.is_none() {
                assert_eq!(
                    plane, None,
                    "{knob:?} names a vacuity plane but has no report to read it off"
                );
                continue;
            };
            with_report += 1;
            let plane =
                plane.unwrap_or_else(|| panic!("{knob:?} has a report but no vacuity plane"));
            let generation = planted(RunFacts::ok().vacuous(plane), "");
            let class = classify(&generation, &rules);
            assert_eq!(class, CampaignClass::Vacuous, "{knob:?} on plane {plane:?}");
            assert!(
                signature(class, &generation).shape.ends_with(plane),
                "{knob:?}: the signature must name plane {plane:?}"
            );
        }
        assert!(
            with_report > 0,
            "this gate proves nothing unless some knob has a report to read"
        );
    }
}
