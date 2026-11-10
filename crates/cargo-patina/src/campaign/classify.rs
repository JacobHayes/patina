//! Structured outcome classification and failure signatures.

use super::Signature;
use super::generation::SIGKILL;
use super::state::json_required_str;
use patina_dst_abi::RunClass;
use std::collections::BTreeMap;

// ===========================================================================
// Classifier (pure) + signatures
// ===========================================================================

/// Whether only comparing two runs of a generation can reach this class, so
/// no single run's facts — and no spec-declared rule — can.
pub(super) const fn is_cross_run(class: RunClass) -> bool {
    matches!(class, RunClass::Nondeterministic)
}

/// Whether a failing generation of this class reached a conclusion — about the
/// guest, or about what patina models and reproduces — as opposed to producing
/// no answer at all: a timeout, a host-side kill, patina's own recorder giving
/// out, a child that could not start. The inconclusive ones are still surfaced
/// and still deduped, but they are not verified by reproduction and do not
/// spend the campaign's novel-signature count, which exists to say "this many
/// DISTINCT things were learned".
pub(super) const fn is_conclusive(class: RunClass) -> bool {
    class.is_failure()
        && !matches!(
            class,
            RunClass::Timeout | RunClass::Internal | RunClass::Error
        )
}

/// The class a whole campaign ends in, from the classes its generations
/// landed in and its coverage gate: the campaign's `result`, and through it
/// its attribution and exit status. A finding in the guest outranks every
/// stop of patina's (the campaign did find something, and the summary lists
/// the rest); an unmet coverage gate is the guest's own assertion failing
/// (a `sometimes!` that never held, a `reachable!` never reached).
pub(super) fn campaign_result(
    classes: impl Iterator<Item = RunClass> + Clone,
    coverage_gate_failed: bool,
) -> RunClass {
    let present = |class: RunClass| classes.clone().any(|seen| seen == class);
    let first_present =
        |candidates: &[RunClass]| candidates.iter().copied().find(|class| present(*class));
    if let Some(finding) = first_present(&[
        RunClass::Violation,
        RunClass::Liveness,
        RunClass::Crash,
        RunClass::Failure,
    ]) {
        return finding;
    }
    if coverage_gate_failed {
        return RunClass::Violation;
    }
    first_present(&[
        RunClass::Nondeterministic,
        RunClass::Vacuous,
        RunClass::Timeout,
        RunClass::Unsupported,
        RunClass::Internal,
        RunClass::Error,
    ])
    .unwrap_or(RunClass::Ok)
}

/// The `fault_reports{}` planes whose `vacuous` bit is a coverage failure. The
/// schedule plane is not one: its vacuity is a runtime finding of its own.
pub(super) const VACUITY_PLANES: &[&str] =
    &["fs", "dns", "net", "entropy", "clock", "custom_op", "swarm"];

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
/// the campaign summary counts them by it.
pub(super) const SHUTDOWN_FAILURE_SHAPE: &str = "stop reason=shutdown_failure";

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
/// `patina.result/v2` envelope reports, in call order.
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
/// `patina.result` envelope reduced to the fields the campaign reads, plus
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
    /// The child process's exit status: the tool's, which follows the run's
    /// class and never the guest's status.
    pub exit_code: i32,
    /// `guest_exit.code` — the status the guest itself exited with.
    pub guest_exit_code: Option<i32>,
    /// The signal the guest died on, from `guest_exit.signal`; without an
    /// envelope, the signal the child itself died on.
    pub signal: Option<i32>,
    /// The signal the child `patina run` process itself died on, if it did.
    pub child_signal: Option<i32>,
    /// The campaign's wall-clock backstop killed this generation.
    pub timed_out: bool,
    /// The child emitted a `patina.result` run envelope. `false` means
    /// patina's own supervisor never reported a run for this generation.
    pub envelope: bool,
    /// `result` — the class the child's own run reported: the one
    /// classification, made once, by the run. `None` without an envelope that
    /// names a class this patina knows.
    pub class: Option<RunClass>,
    /// `stop.reason` — what stopped the run, when it did not end clean.
    pub stop: Option<String>,
    /// `stop.guest_exit_code` — the status the GUEST itself reached, when the
    /// stop replaced it.
    pub stop_guest_exit_code: Option<i32>,
    /// `trace_unusable` — the class is the guest's own while the run's
    /// recording was lost.
    pub trace_unusable: bool,
    /// `replay_divergence` — a `replay` that ran but did not follow its trace
    /// (an operation past its end, a mismatched operation or outcome, recorded
    /// operations left over), as the runtime reported it on the facts channel;
    /// or a crash-restart replay that departed from its recording at the crash,
    /// as the supervisor reports it (`crash_restart.terminal_outcome.kind`).
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
    /// guest's full code, the signal, and what stopped the run with the
    /// status the guest reached under it.
    pub(crate) fn exit_status(&self) -> String {
        let mut exit = format!("exit={}", self.exit_code);
        if let Some(code) = self.guest_exit_code {
            exit.push_str(&format!(" guest_exit={code}"));
        }
        if let Some(signal) = self.signal {
            exit.push_str(&format!(" signal={signal}"));
        }
        if let Some(stop) = &self.stop {
            exit.push_str(&format!(" stop={stop}"));
        }
        if let Some(code) = self.stop_guest_exit_code {
            exit.push_str(&format!(" stop_guest_exit={code}"));
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

    /// Whether the child run itself was killed from outside: SIGKILL, which
    /// it cannot deliver to itself, catch or survive. A guest killed under a
    /// child that lived to report is the child's to classify (a host kill it
    /// files `internal` itself; a SIGKILL the guest sent itself is its crash).
    fn child_killed(&self) -> bool {
        self.child_signal == Some(SIGKILL)
    }

    /// Whether the generation ended on a kill from outside, whoever saw it:
    /// the campaign (the child died) or the child (its guest did).
    fn host_killed(&self) -> bool {
        self.child_killed() || self.stop.as_deref() == Some(crate::output::HOST_KILL_STOP)
    }

    /// The name of the fault signal the guest died on, if it died on one.
    fn fault_signal(&self) -> Option<&'static str> {
        let signal = self.signal?;
        FAULT_SIGNALS
            .iter()
            .find(|(number, _)| *number == signal)
            .map(|(_, name)| *name)
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
    /// The GUEST's own captured stdout and stderr, joined, as the child's
    /// envelope carried them; `None` without an envelope. What a signature's
    /// fallback reads when there is one: the child supervisor's own stderr (a
    /// build line, a pre-run advisory) names per-run paths and is never the
    /// guest's finding, so it must not be able to become a failure's shape.
    pub guest_output: Option<String>,
    /// The envelope's `stop.detail`: patina's own line naming what stopped the
    /// run. Text, so it lives here; read ONLY to tell one unsupported
    /// operation's signature from another's.
    pub stop_detail: Option<String>,
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

impl GenerationFacts {
    /// The text a finding's evidence is cut from when no structured fact names
    /// it: the guest's own streams, or without an envelope everything the
    /// child printed, which is all there is.
    fn evidence(&self) -> &str {
        self.guest_output.as_deref().unwrap_or(&self.output)
    }
}

/// Per-guest classification rules a campaign spec declares (`classify` in the
/// spec JSON). The grep mechanism survives here, and only here: as explicit,
/// versioned, per-guest configuration rather than a string baked into patina.
///
/// Keyed by [`RunClass`], whose `Ord` is the severity order, so two matching
/// declarations always resolve to the more severe class — deterministically.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassifyRules {
    /// class -> output line substrings.
    pub(super) patterns: BTreeMap<RunClass, Vec<String>>,
    /// class -> guest exit codes.
    pub(super) exit_codes: BTreeMap<RunClass, Vec<i32>>,
}

impl ClassifyRules {
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty() && self.exit_codes.is_empty()
    }

    /// The class this guest's declared rules assign, if any. Patterns are checked
    /// before exit codes (a matched line is more specific than a bare code), and
    /// both in severity order.
    fn declared(&self, generation: &GenerationFacts) -> Option<RunClass> {
        for (class, needles) in &self.patterns {
            if needles
                .iter()
                .any(|needle| generation.output.contains(needle.as_str()))
            {
                return Some(*class);
            }
        }
        // The GUEST's exit status: the child's own follows the run's class and
        // says nothing a rule could key on.
        for (class, codes) in &self.exit_codes {
            if generation
                .facts
                .guest_exit_code
                .is_some_and(|code| codes.contains(&code))
            {
                return Some(*class);
            }
        }
        None
    }
}

/// Classify one generation: the class its own run reported, adjusted by what
/// only the campaign knows, plus the spec's declared rules.
///
/// The run's class takes precedence: a declared rule can only speak when the
/// run found nothing structural of its own (`ok`, or a bare `failure`), so a
/// pattern can ADD a finding a level-1 guest would otherwise hide but can never
/// downgrade one patina detected.
pub fn classify(generation: &GenerationFacts, rules: &ClassifyRules) -> RunClass {
    let built_in = built_in_class(&generation.facts);
    if matches!(built_in, RunClass::Ok | RunClass::Failure)
        && let Some(declared) = rules.declared(generation)
    {
        return declared;
    }
    built_in
}

/// The class of a generation, with no guest output in sight: the one its own
/// `patina run` reported, which the campaign does not second-guess, under
/// the three facts only the campaign has. Total: a generation with no class
/// to read lands in `internal`, never in `ok`.
fn built_in_class(facts: &RunFacts) -> RunClass {
    // 1. The campaign's own wall-clock backstop killed this generation: it hung
    //    in a way neither the virtual-time watchdog nor the child's bounds
    //    caught, so the outcome is inconclusive, never a silent `ok`.
    if facts.timed_out {
        return RunClass::Timeout;
    }
    // 2. The child run was killed from OUTSIDE — SIGKILL. The kernel OOM
    //    killer under parallel campaign load is the common source. Checked
    //    before the child's own class because the child may have been killed
    //    after it reported one, or along with its guest.
    if facts.child_killed() {
        return RunClass::Internal;
    }
    // 3. No class to read: the child `patina run` left no run envelope (a
    //    supervisor error, a child that died), or named a class this patina
    //    does not know. Patina could not report a result for this generation.
    let Some(class) = facts.class else {
        return RunClass::Internal;
    };
    // 3a. The class the child reported and the status it then exited with must
    //     agree, since the status is a function of the class: a child that
    //     reported one outcome and ended another way (it died after printing
    //     its envelope) did not finish the run it described. Never the
    //     envelope's word over the process's.
    if facts.exit_code != class.exit_code() {
        return RunClass::Internal;
    }
    // 4. A clean run whose fault or exploration plane went inert is a coverage
    //    failure, and the signature names the planes. Vacuity is judged only
    //    here, on a run that otherwise passed: a run that failed on its own
    //    keeps that failure as its headline, exactly as it would without the
    //    fault knobs that went inert.
    if class == RunClass::Ok && !facts.vacuous_planes.is_empty() {
        return RunClass::Vacuous;
    }
    class
}

/// Build a signature from a classified generation.
///
/// The shape comes from the same structured facts the class did, so two
/// generations that hit the same invariant dedup to one signature regardless of
/// how the guest worded its output. Only when the facts carry nothing for the
/// class (a bare `failure`, a declared-pattern class) does it fall back to
/// the captured output, which is all there is in those cases.
pub fn signature(class: RunClass, generation: &GenerationFacts) -> Signature {
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
pub(super) fn primary_finding(class: RunClass, generation: &GenerationFacts) -> String {
    let shape = primary_finding_shape(class, generation);
    // A generation whose class is the GUEST's while patina's own recorder also
    // gave out is reproducible only up to a point: the finding stands, but the
    // trace it would be replayed from was never written. Say so on the shape
    // itself — it is the line triage reads — rather than let a printed
    // `reproduce` command promise an artifact that is not there.
    if generation.facts.trace_unusable && class.is_finding() {
        return format!("{shape} trace=unusable");
    }
    shape
}

/// The class's own most representative description, before any cross-cutting
/// annotation [`primary_finding`] adds.
fn primary_finding_shape(class: RunClass, generation: &GenerationFacts) -> String {
    let facts = &generation.facts;
    // What stopped the run, as the run named it: the reason's token, which is
    // patina's own and stable.
    let stop_reason = || {
        facts
            .stop
            .as_ref()
            .map(|reason| format!("stop reason={reason}"))
    };
    let structured = match class {
        RunClass::Liveness => facts
            .has_finding("liveness")
            .map(|finding| format!("liveness kind={}", finding.kind))
            .or_else(stop_reason),
        RunClass::Violation => facts
            .has_verdict("violation")
            .map(|verdict| format!("verdict kind=violation label={}", verdict.label))
            .or_else(stop_reason),
        // A hardware/OS fault: the guest died executing bad code without ever
        // reaching `abort()`. Name the signal — it is the whole finding — and
        // keep the guest's last words after it for triage.
        RunClass::Crash if facts.fault_signal().is_some() => {
            facts
                .fault_signal()
                .map(|signal| match death_attribution(generation) {
                    Some(evidence) => format!("guest_fault signal={signal} {evidence}"),
                    None => format!("guest_fault signal={signal}"),
                })
        }
        // The guest's own abort, which it may have claimed with an
        // `abort_intent` verdict. Without one, `unattributed` is the honest
        // head — nothing structured says WHY — but it must not be the whole
        // shape: on a guest with no cooperative SDK (the common case) every
        // distinct abort in a campaign then dedups into ONE useless signature.
        // Recover what the streams do carry, so two different aborts stay two
        // findings and each names its own cause.
        RunClass::Crash => Some(match facts.has_verdict("abort_intent") {
            Some(verdict) => format!("guest_abort label={}", verdict.label),
            None => match death_attribution(generation) {
                Some(evidence) => format!("guest_abort unattributed {evidence}"),
                None => "guest_abort unattributed".to_string(),
            },
        }),
        // What patina does not model is named by the stop's own detail (the
        // syscall, the symbol, the operation), so two different gaps stay two
        // signatures; its numbers collapse with the rest of the shape.
        RunClass::Unsupported => stop_reason().map(|reason| {
            match generation
                .stop_detail
                .as_deref()
                .and_then(|detail| detail.lines().next())
                .map(str::trim)
                .filter(|detail| !detail.is_empty())
            {
                Some(detail) => format!("{reason} {detail}"),
                None => reason,
            }
        }),
        // A host-side kill has ONE shape, always: there is no finding in it to
        // describe, and every such generation must dedup onto the same entry
        // rather than spraying novel signatures made of whatever the guest
        // happened to have printed when the kernel took it away.
        RunClass::Internal if facts.host_killed() => Some(HOST_KILL_SHAPE.to_string()),
        // A failure of patina's own is named by its reason alone: its detail
        // carries per-run paths and pids, which would fragment the signature.
        // A timeout the run itself reported (the compute bound, the step
        // budget) likewise; the campaign's own backstop left only its marker
        // in the output, which the fallback below reads.
        RunClass::Timeout if facts.timed_out => None,
        RunClass::Internal | RunClass::Timeout | RunClass::Error | RunClass::Nondeterministic => {
            stop_reason()
        }
        // The inert planes are the whole finding, in a fixed order so two
        // generations with the same planes share a signature.
        RunClass::Vacuous => {
            let mut planes = facts.vacuous_planes.clone();
            planes.sort();
            Some(format!("vacuous planes={}", planes.join(",")))
        }
        // A bare failure carries no fact: its shape is the guest's own words.
        RunClass::Failure | RunClass::Ok => None,
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
        .evidence()
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
/// 2. **Supervisor pre-run advisories**, printed by the child `patina run`
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
/// `patina: ...` CLI errors, and the campaign's own
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
    let lines: Vec<&str> = generation.evidence().lines().map(str::trim).collect();
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

    /// A campaign ends in one class: a finding in the guest outranks every
    /// stop of patina's, an unmet coverage gate is the guest's, and only a
    /// campaign with neither exits 2 for what patina could not do.
    #[test]
    fn a_campaign_ends_in_the_class_that_decides_its_exit() {
        use RunClass::*;
        for (classes, gate_failed, want) in [
            (vec![Ok], false, Ok),
            (vec![Ok, Unsupported, Failure, Internal], false, Failure),
            (vec![Ok, Failure, Violation], false, Violation),
            (vec![Ok, Internal], true, Violation),
            (vec![Ok, Internal, Unsupported], false, Unsupported),
            (vec![Ok, Vacuous], false, Vacuous),
            (vec![Ok, Timeout, Nondeterministic], false, Nondeterministic),
        ] {
            let result = campaign_result(classes.iter().copied(), gate_failed);
            assert_eq!(result, want, "{classes:?} gate_failed={gate_failed}");
            assert_eq!(
                result.exit_code() == 1,
                gate_failed || classes.iter().any(|class| class.is_finding()),
                "{classes:?}"
            );
        }
    }

    /// Every class a single generation can land in: the run's own passes
    /// through, and the campaign's three overrides each fire.
    #[test]
    fn a_generation_lands_in_its_runs_class_under_the_campaigns_overrides() {
        let rules = ClassifyRules::default();
        for class in RunClass::ALL.iter().copied() {
            if is_cross_run(class) || class == RunClass::Vacuous {
                continue;
            }
            let facts = RunFacts::ok().stopped(class, "reason");
            assert_eq!(classify(&planted(facts, ""), &rules), class);
        }
        assert_eq!(
            classify(&planted(RunFacts::ok().vacuous("fs"), ""), &rules),
            RunClass::Vacuous
        );
        assert_eq!(
            classify(&planted(RunFacts::ok().timed_out(), ""), &rules),
            RunClass::Timeout
        );
        assert_eq!(
            classify(&planted(RunFacts::ok().no_envelope(), ""), &rules),
            RunClass::Internal
        );
    }

    #[test]
    fn declared_rules_add_findings_but_never_downgrade_one() {
        let rules = declared_rules_fixture();
        // A level-1 guest's own text, with zero guest modification.
        assert_eq!(
            classify(&planted(RunFacts::ok(), "checksum mismatch"), &rules),
            RunClass::Violation
        );
        assert_eq!(
            classify(&planted(RunFacts::ok().exit(3), ""), &rules),
            RunClass::Violation
        );
        // The same text with no rule declared stays OK: the rule classifies, not
        // the string.
        assert_eq!(
            classify(
                &planted(RunFacts::ok(), "checksum mismatch"),
                &ClassifyRules::default()
            ),
            RunClass::Ok
        );
        // A class the run itself reached always wins over a declared rule.
        assert_eq!(
            classify(
                &planted(
                    RunFacts::ok()
                        .exit(3)
                        .stopped(RunClass::Unsupported, "not_modeled"),
                    "checksum mismatch"
                ),
                &rules
            ),
            RunClass::Unsupported
        );
    }

    /// Two operations patina does not model are two signatures, named by the
    /// stop's own detail; a failure of patina's own is one, by its reason.
    #[test]
    fn an_unsupported_stop_is_signed_by_what_was_reached() {
        let stopped = |class: RunClass, detail: &str| {
            let mut generation = planted(RunFacts::ok().stopped(class, "reason"), "");
            generation.stop_detail = Some(detail.to_string());
            signature(class, &generation)
        };
        assert_ne!(
            stopped(RunClass::Unsupported, "the guest called fork"),
            stopped(RunClass::Unsupported, "the guest called dlopen")
        );
        assert_eq!(
            stopped(RunClass::Unsupported, "syscall 435 at pc 0x7f01"),
            stopped(RunClass::Unsupported, "syscall 435 at pc 0x7f02")
        );
        assert_eq!(
            stopped(RunClass::Internal, "scratch /tmp/a"),
            stopped(RunClass::Internal, "scratch /tmp/b")
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
            assert_eq!(class, RunClass::Vacuous, "{knob:?} on plane {plane:?}");
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
