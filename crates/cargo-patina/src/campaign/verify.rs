//! Reproduction verification: a campaign checks that what it reports
//! reproduces.
//!
//! Before a novel finding signature is reported, the campaign runs that
//! finding's own reproduce path — `replay` of its saved trace, or the seeded
//! re-run a traceless failure prints — and compares the two outcomes exactly:
//! the signature, the exit status, the unnormalized finding line, the verdict
//! rows with their details and, when both runs left a trace, the trace's
//! content digest. A seeded sample of clean generations is run twice the same
//! way, so a leak that never fails a run is caught too. A mismatch is
//! [`CampaignClass::Nondeterminism`], and both outcomes travel with it.
//!
//! The signature's policy annotation (`bug_depth=N`, the PCT change points and
//! starvation exclusions the seeded schedule hit) describes how the run
//! explored, not what it reached. A rerun explores again and must hit the same
//! ones; a replay follows the recorded selections, makes no scheduling
//! decisions and reports none, so a replay leaves the annotation out of the
//! comparison.
//!
//! A replay that does not follow its trace is a mismatch on its own, whatever
//! the refusal that reports it: the replayed run is not the recorded one. Any
//! other reproduction attempt patina could not complete (a timeout, a host
//! kill, a recorder failure — every non-finding failure class) proves nothing
//! either way: it is [`VerifyStatus::Infra`], and the generation keeps the
//! class it was observed with.

use super::classify::primary_finding;
use super::generation::{GenerationFiles, facts_from_envelope, run_generation, run_replay};
use super::state::{CampaignState, json_optional_str, json_required_str};
use super::{CampaignClass, ClassifyRules, GenerationFacts, GenerationRun, Signature};
use super::{classify, signature};
use crate::CliError;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// One clean generation in this many is run twice. Cheap (a sixteenth more
/// child runs), and a stride rather than a rate so a campaign of any length
/// past the stride samples, with no unlucky campaign that samples nothing.
pub(super) const CLEAN_RERUN_STRIDE: u64 = 16;

/// Whether `generation` is one of the clean generations a campaign re-runs: a
/// pure function of the campaign seed, so a re-run of the campaign samples the
/// same generations.
pub(super) fn samples_clean_rerun(seed_base: u64, generation: u64) -> bool {
    let digest = Sha256::digest(format!("patina-campaign-verify-{seed_base}"));
    generation % CLEAN_RERUN_STRIDE == u64::from(digest[0]) % CLEAN_RERUN_STRIDE
}

/// The content digest of the validated trace bundle at `path`, or `None` when
/// the run left no valid trace (a mid-run abort, a timeout).
pub(super) fn trace_digest(path: &Path) -> Option<String> {
    let bytes = patina_dst_trace::TraceBundle::load(path)
        .ok()?
        .to_bytes()
        .ok()?;
    Some(patina_dst_trace::Sha256Digest(Sha256::digest(&bytes).into()).to_string())
}

/// The signature a nondeterministic generation is filed under: the observed
/// outcome's own signature (`None` for a clean run), so every repeat of a
/// signature found not to reproduce dedups onto it. The reproduction attempt's
/// outcome is deliberately not part of it — it is the half that varies.
pub(super) fn nondeterminism_signature(observed: Option<&Signature>) -> Signature {
    let (shape, policy) = match observed {
        Some(observed) => (
            format!("observed={} {}", observed.class.as_str(), observed.shape),
            observed.policy.clone(),
        ),
        None => (
            format!("observed={}", CampaignClass::Ok.as_str()),
            String::new(),
        ),
    };
    Signature {
        class: CampaignClass::Nondeterminism,
        shape,
        policy,
    }
}

/// The comparable outcome of one execution of a generation.
///
/// The signature is a dedup key and deliberately lossy (it collapses numbers,
/// and its verdicts drop their details), so it cannot certify that two runs of
/// one generation agree. The exact fields beside it can: each is something a
/// deterministic replay reproduces byte for byte (the guest's own output under
/// patina's virtual time and seeded entropy, its verdict calls, its exit) and
/// excludes what legitimately differs between a recording and its replay
/// (patina's own diagnostics, which name per-run paths and are never the
/// finding line).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Observation {
    pub(super) class: CampaignClass,
    /// The failure signature key without its policy annotation; `None` for a
    /// clean run.
    pub(super) signature: Option<String>,
    /// The failure signature's policy annotation, empty when it has none or
    /// the run was clean.
    pub(super) policy: String,
    /// The exit status: the process's code, the guest's full code, the signal,
    /// and patina's refusal class with the status the guest reached under it.
    pub(super) exit: String,
    /// The exact line the signature's shape is cut from; `None` for a clean
    /// run.
    pub(super) finding: Option<String>,
    /// The verdict rows exactly as reported, details included.
    pub(super) verdicts: Vec<String>,
    /// [`trace_digest`] of the run's trace, when it left a valid one.
    pub(super) trace: Option<String>,
    /// This run was a replay that did not follow its trace.
    pub(super) replay_diverged: bool,
}

impl Observation {
    pub(super) fn new(
        class: CampaignClass,
        facts: &GenerationFacts,
        trace: Option<String>,
    ) -> Self {
        let failure = class.is_failure().then(|| signature(class, facts));
        Observation {
            class,
            signature: failure.as_ref().map(Signature::outcome_key),
            policy: failure.map(|failure| failure.policy).unwrap_or_default(),
            exit: facts.facts.exit_status(),
            finding: class.is_failure().then(|| primary_finding(class, facts)),
            verdicts: facts.exact_verdicts.clone(),
            trace,
            replay_diverged: facts.facts.replay_diverged,
        }
    }

    /// Whether `other`, reached along `path`, is the same outcome on every
    /// exact axis. A replay explores nothing, so it is not held to the
    /// recording's policy annotation.
    fn agrees_with(&self, other: &Observation, path: VerifyPath) -> bool {
        let traces_agree = match (&self.trace, &other.trace) {
            (Some(first), Some(second)) => first == second,
            _ => true,
        };
        let policies_agree = path == VerifyPath::Replay || self.policy == other.policy;
        self.signature == other.signature
            && policies_agree
            && self.exit == other.exit
            && self.finding == other.finding
            && self.verdicts == other.verdicts
            && traces_agree
    }

    fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("class".into(), self.class.as_str().into());
        if let Some(signature) = &self.signature {
            map.insert("signature".into(), signature.clone().into());
        }
        if !self.policy.is_empty() {
            map.insert("policy".into(), self.policy.clone().into());
        }
        map.insert("exit".into(), self.exit.clone().into());
        if let Some(finding) = &self.finding {
            map.insert("finding".into(), finding.clone().into());
        }
        map.insert("verdicts".into(), self.verdicts.clone().into());
        if let Some(trace) = &self.trace {
            map.insert("trace".into(), trace.clone().into());
        }
        if self.replay_diverged {
            map.insert("replay_diverged".into(), true.into());
        }
        serde_json::Value::Object(map)
    }

    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "verification outcome must be an object".to_string())?;
        let class_text = json_required_str(object, "class")?;
        let verdicts = object
            .get("verdicts")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "verification outcome verdicts must be an array".to_string())?
            .iter()
            .map(|row| {
                row.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "verification outcome verdict must be a string".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Observation {
            class: CampaignClass::parse(class_text)
                .ok_or_else(|| format!("unknown campaign class {class_text:?}"))?,
            signature: json_optional_str(object, "signature")?,
            policy: json_optional_str(object, "policy")?.unwrap_or_default(),
            exit: json_required_str(object, "exit")?.to_string(),
            finding: json_optional_str(object, "finding")?,
            verdicts,
            trace: json_optional_str(object, "trace")?,
            replay_diverged: object
                .get("replay_diverged")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        })
    }

    /// One line for the human report.
    pub(super) fn describe(&self) -> String {
        let diverged = if self.replay_diverged {
            " replay_diverged"
        } else {
            ""
        };
        format!(
            "{} {} finding={} verdicts=[{}] trace={}{diverged}",
            self.class.as_str(),
            self.exit,
            self.finding.as_deref().unwrap_or("-"),
            self.verdicts.join(","),
            self.trace.as_deref().unwrap_or("-"),
        )
    }
}

/// How a generation was run again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VerifyPath {
    /// `cargo patina replay` of the saved trace.
    Replay,
    /// A seeded re-run with the generation's recorded knobs.
    Rerun,
}

impl VerifyPath {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            VerifyPath::Replay => "replay",
            VerifyPath::Rerun => "rerun",
        }
    }
}

/// What running a generation again showed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VerifyStatus {
    /// The second run reached the same outcome.
    Reproduced,
    /// The second run reached a different outcome.
    Nondeterministic,
    /// The second run produced no answer (a non-finding failure class that is
    /// not a replay divergence), so reproducibility is unknown.
    Infra,
}

impl VerifyStatus {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            VerifyStatus::Reproduced => "reproduced",
            VerifyStatus::Nondeterministic => "nondeterministic",
            VerifyStatus::Infra => "infra",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        [Self::Reproduced, Self::Nondeterministic, Self::Infra]
            .into_iter()
            .find(|status| status.as_str() == value)
    }
}

/// One reproduction attempt and both outcomes it compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Verification {
    pub(super) path: VerifyPath,
    pub(super) status: VerifyStatus,
    pub(super) observed: Observation,
    pub(super) reproduction: Observation,
}

impl Verification {
    /// Compare a generation's observed outcome with a reproduction attempt.
    ///
    /// A replay that diverged from its trace is nondeterminism before anything
    /// else: the refusal that reports the divergence (a shim fatal, a failed
    /// shutdown) can be a non-finding class, or come after the same verdict,
    /// and neither makes the replayed run the recorded one. Then a reproduction
    /// patina could not complete is infra. Otherwise the outcomes must agree on
    /// every exact axis; the signature comparison is the class comparison too,
    /// since a signature key leads with its class and is absent exactly for
    /// `OK`.
    pub(super) fn judge(
        path: VerifyPath,
        observed: Observation,
        reproduction: Observation,
    ) -> Self {
        let status = if reproduction.replay_diverged {
            VerifyStatus::Nondeterministic
        } else if reproduction.class.is_failure() && !reproduction.class.is_finding() {
            VerifyStatus::Infra
        } else if observed.agrees_with(&reproduction, path) {
            VerifyStatus::Reproduced
        } else {
            VerifyStatus::Nondeterministic
        };
        Verification {
            path,
            status,
            observed,
            reproduction,
        }
    }

    /// The class the generation is reported under.
    pub(super) fn class(&self) -> CampaignClass {
        match self.status {
            VerifyStatus::Nondeterministic => CampaignClass::Nondeterminism,
            VerifyStatus::Reproduced | VerifyStatus::Infra => self.observed.class,
        }
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "path": self.path.as_str(),
            "status": self.status.as_str(),
            "observed": self.observed.to_json(),
            "reproduction": self.reproduction.to_json(),
        })
    }

    pub(super) fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "verification must be an object".to_string())?;
        let path = match json_required_str(object, "path")? {
            "replay" => VerifyPath::Replay,
            "rerun" => VerifyPath::Rerun,
            other => return Err(format!("unknown verification path {other:?}")),
        };
        let status_text = json_required_str(object, "status")?;
        let field = |key: &str| {
            object
                .get(key)
                .ok_or_else(|| format!("verification missing {key}"))
        };
        let verification = Verification {
            path,
            status: VerifyStatus::parse(status_text)
                .ok_or_else(|| format!("unknown verification status {status_text:?}"))?,
            observed: Observation::from_json(field("observed")?)?,
            reproduction: Observation::from_json(field("reproduction")?)?,
        };
        if verification.to_json() != *value {
            return Err("verification is not in canonical lossless form".to_string());
        }
        Ok(verification)
    }
}

/// The campaign-level clean-rerun tally: the reruns that left no trace in the
/// notable runs, because their generation stayed `OK`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CleanReruns {
    /// Clean generations run a second time.
    pub(super) runs: u64,
    /// Of those, the second runs that produced no answer.
    pub(super) infra: u64,
}

/// What a campaign's reproduction verification did, for the report: derived
/// from the notable runs (every verified finding, and every clean rerun that
/// did not reproduce, is one) and the clean-rerun tally.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct VerificationSummary {
    pub(super) enabled: bool,
    pub(super) findings_reproduced: u64,
    pub(super) findings_nondeterministic: u64,
    pub(super) findings_infra: u64,
    pub(super) clean_reruns: u64,
    pub(super) clean_nondeterministic: u64,
    pub(super) clean_infra: u64,
}

impl VerificationSummary {
    pub(super) fn of(state: &CampaignState) -> Self {
        let mut summary = VerificationSummary {
            enabled: state.spec.verify,
            clean_reruns: state.clean_reruns.runs,
            clean_infra: state.clean_reruns.infra,
            ..VerificationSummary::default()
        };
        for verification in state
            .notable_runs
            .iter()
            .filter_map(|run| run.verification.as_ref())
        {
            let clean = verification.observed.class == CampaignClass::Ok;
            match (clean, verification.status) {
                (true, VerifyStatus::Nondeterministic) => summary.clean_nondeterministic += 1,
                // A clean rerun that reproduced, or produced no answer, leaves
                // its generation OK and is counted by the tally instead.
                (true, _) => {}
                (false, VerifyStatus::Reproduced) => summary.findings_reproduced += 1,
                (false, VerifyStatus::Nondeterministic) => summary.findings_nondeterministic += 1,
                (false, VerifyStatus::Infra) => summary.findings_infra += 1,
            }
        }
        summary
    }

    fn findings_verified(&self) -> u64 {
        self.findings_reproduced + self.findings_nondeterministic + self.findings_infra
    }

    /// The machine-readable summary line of the human report.
    pub(super) fn line(&self) -> String {
        if !self.enabled {
            return "PATINA_CAMPAIGN_VERIFY state=off".to_string();
        }
        format!(
            "PATINA_CAMPAIGN_VERIFY state=on findings_verified={} findings_reproduced={} findings_nondeterministic={} findings_infra={} clean_reruns={} clean_nondeterministic={} clean_infra={}",
            self.findings_verified(),
            self.findings_reproduced,
            self.findings_nondeterministic,
            self.findings_infra,
            self.clean_reruns,
            self.clean_nondeterministic,
            self.clean_infra,
        )
    }

    pub(super) fn to_json(self) -> serde_json::Value {
        if !self.enabled {
            return serde_json::json!({ "state": "off" });
        }
        serde_json::json!({
            "state": "on",
            "clean_rerun_stride": CLEAN_RERUN_STRIDE,
            "findings": {
                "verified": self.findings_verified(),
                "reproduced": self.findings_reproduced,
                "nondeterministic": self.findings_nondeterministic,
                "infra": self.findings_infra,
            },
            "clean": {
                "reruns": self.clean_reruns,
                "nondeterministic": self.clean_nondeterministic,
                "infra": self.clean_infra,
            },
        })
    }
}

/// Everything a reproduction attempt needs that does not vary by generation.
pub(super) struct Verifier<'a> {
    pub(super) self_exe: &'a Path,
    pub(super) artifact: &'a Path,
    pub(super) invocation: &'a [String],
    pub(super) guest_tail: &'a [String],
    pub(super) timeout_secs: u64,
    pub(super) rules: &'a ClassifyRules,
    pub(super) traces_dir: &'a Path,
}

/// One generation to run again: its seed and knobs, and whether it ran with
/// an edge-coverage map (part of the experiment, so the second run gets one).
pub(super) struct Attempt<'a> {
    pub(super) generation: u64,
    pub(super) seed: u64,
    pub(super) flags: &'a [String],
    pub(super) coverage: bool,
}

impl Verifier<'_> {
    /// Run a generation's reproduce path: replay its saved trace, or re-run its
    /// seed and knobs when it left none.
    pub(super) fn reproduce(
        &self,
        attempt: &Attempt<'_>,
        observed: Observation,
        saved_trace: Option<&str>,
    ) -> Result<Verification, CliError> {
        let Some(trace) = saved_trace else {
            return self.rerun(attempt, observed);
        };
        let run = run_replay(
            self.self_exe,
            self.artifact,
            Path::new(trace),
            self.invocation,
            self.timeout_secs,
        )?;
        let reproduction = Observation::new(classify(&run.facts, self.rules), &run.facts, None);
        Ok(Verification::judge(
            VerifyPath::Replay,
            observed,
            reproduction,
        ))
    }

    /// Run a generation a second time from its seed and knobs, recording into
    /// scratch so the two traces can be compared.
    pub(super) fn rerun(
        &self,
        attempt: &Attempt<'_>,
        observed: Observation,
    ) -> Result<Verification, CliError> {
        let generation = attempt.generation;
        let trace_path = self
            .traces_dir
            .join(format!("generation-{generation}.verify.patina"));
        let coverage_path: Option<PathBuf> = attempt.coverage.then(|| {
            self.traces_dir
                .join(format!("generation-{generation}.verify.covmap"))
        });
        let scratch = [Some(trace_path.as_path()), coverage_path.as_deref()];
        for path in scratch.into_iter().flatten() {
            let _ = std::fs::remove_file(path);
            crate::remove_dead_scratch(path);
        }
        let run: Result<GenerationRun, CliError> = run_generation(
            self.self_exe,
            self.artifact,
            attempt.seed,
            attempt.flags,
            GenerationFiles {
                trace_path: &trace_path,
                coverage_out: coverage_path.as_deref(),
            },
            self.guest_tail,
            self.timeout_secs,
        );
        let digest = trace_digest(&trace_path);
        for path in scratch.into_iter().flatten() {
            let _ = std::fs::remove_file(path);
            crate::remove_dead_scratch(path);
        }
        let run = run?;
        let reproduction = Observation::new(classify(&run.facts, self.rules), &run.facts, digest);
        Ok(Verification::judge(
            VerifyPath::Rerun,
            observed,
            reproduction,
        ))
    }
}

/// The verification outcomes `campaign --selftest` proves, as
/// `(name, want, got)` class checks: every comparison axis is load-bearing (a
/// red twin that differs only there), a replay divergence is nondeterminism
/// whatever class carries it, any other reproduction patina could not finish
/// keeps the observed class, and only a rerun is held to the policy annotation.
pub(super) fn selftest_class_checks() -> Vec<(&'static str, CampaignClass, CampaignClass)> {
    let failure = || Observation {
        class: CampaignClass::Violation,
        signature: Some("VIOLATION|verdict kind=violation label=x-#|".into()),
        policy: String::new(),
        exit: "exit=1".into(),
        finding: Some("verdict kind=violation label=x-1".into()),
        verdicts: vec![r#"{"detail":"1","kind":"violation","label":"x-1","seq":0}"#.into()],
        trace: None,
        replay_diverged: false,
    };
    let clean = |trace: &str| Observation {
        class: CampaignClass::Ok,
        signature: None,
        policy: String::new(),
        exit: "exit=0".into(),
        finding: None,
        verdicts: Vec::new(),
        trace: Some(trace.into()),
        replay_diverged: false,
    };
    let infra = || Observation {
        class: CampaignClass::Infra,
        signature: Some("INFRA|refusal class=shutdown_failure|".into()),
        policy: String::new(),
        exit: "exit=134 signal=6 refusal=shutdown_failure refusal_guest_exit=0".into(),
        finding: Some("refusal class=shutdown_failure".into()),
        verdicts: Vec::new(),
        trace: None,
        replay_diverged: false,
    };
    let judged =
        |path, observed, reproduction| Verification::judge(path, observed, reproduction).class();
    let differing = |change: fn(&mut Observation)| {
        let mut reproduction = failure();
        change(&mut reproduction);
        judged(VerifyPath::Replay, failure(), reproduction)
    };
    // A seeded run that hit change points, and a run of it that hit none.
    let explored = || {
        let mut run = failure();
        run.policy = "bug_depth=2".into();
        run
    };
    let unexplored = || {
        let mut run = failure();
        run.policy = "bug_depth=0".into();
        run
    };
    let mut other_class = clean("sha256:a");
    other_class.trace = None;
    let mut diverged_infra = infra();
    diverged_infra.replay_diverged = true;
    let mut diverged_same_verdict = failure();
    diverged_same_verdict.replay_diverged = true;
    // A guest's exit code as its envelope reports it, beside the process
    // status the campaign observes, which keeps only the low eight bits.
    let exited = |code: i64| {
        let mut facts = facts_from_envelope(
            &serde_json::json!({"exit_code": code, "guest_exit": {"code": code}}),
        );
        facts.exit_code = (code & 0xff) as i32;
        Observation::new(
            CampaignClass::Unclassified,
            &super::selftest::planted(facts, ""),
            None,
        )
    };
    vec![
        (
            "verify-guest-exit-past-the-process-status-is-nondeterminism",
            CampaignClass::Nondeterminism,
            judged(VerifyPath::Replay, exited(3), exited(259)),
        ),
        (
            "verify-replay-that-reproduces-keeps-class",
            CampaignClass::Violation,
            judged(VerifyPath::Replay, failure(), failure()),
        ),
        (
            "verify-signature-mismatch-is-nondeterminism",
            CampaignClass::Nondeterminism,
            differing(|run| {
                run.signature = Some("VIOLATION|verdict kind=violation label=y|".into())
            }),
        ),
        (
            "verify-exit-mismatch-is-nondeterminism",
            CampaignClass::Nondeterminism,
            differing(|run| run.exit = "exit=2".into()),
        ),
        (
            "verify-numbers-the-signature-collapses-are-nondeterminism",
            CampaignClass::Nondeterminism,
            differing(|run| run.finding = Some("verdict kind=violation label=x-2".into())),
        ),
        (
            "verify-verdict-detail-mismatch-is-nondeterminism",
            CampaignClass::Nondeterminism,
            differing(|run| {
                run.verdicts =
                    vec![r#"{"detail":"2","kind":"violation","label":"x-1","seq":0}"#.into()]
            }),
        ),
        (
            "verify-replay-is-not-held-to-the-seeded-policy",
            CampaignClass::Violation,
            judged(VerifyPath::Replay, explored(), unexplored()),
        ),
        (
            "verify-rerun-policy-mismatch-is-nondeterminism",
            CampaignClass::Nondeterminism,
            judged(VerifyPath::Rerun, explored(), unexplored()),
        ),
        (
            "verify-class-mismatch-is-nondeterminism",
            CampaignClass::Nondeterminism,
            judged(VerifyPath::Rerun, failure(), other_class),
        ),
        (
            "verify-clean-rerun-same-trace-stays-ok",
            CampaignClass::Ok,
            judged(VerifyPath::Rerun, clean("sha256:a"), clean("sha256:a")),
        ),
        (
            "verify-clean-rerun-trace-mismatch",
            CampaignClass::Nondeterminism,
            judged(VerifyPath::Rerun, clean("sha256:a"), clean("sha256:b")),
        ),
        (
            "verify-infra-reproduction-keeps-class",
            CampaignClass::Violation,
            judged(VerifyPath::Rerun, failure(), infra()),
        ),
        (
            "verify-replay-divergence-under-an-infra-refusal-is-nondeterminism",
            CampaignClass::Nondeterminism,
            judged(VerifyPath::Replay, failure(), diverged_infra),
        ),
        (
            "verify-replay-divergence-after-the-same-verdict-is-nondeterminism",
            CampaignClass::Nondeterminism,
            judged(VerifyPath::Replay, failure(), diverged_same_verdict),
        ),
    ]
}

/// The clean-rerun sample's `campaign --selftest` detectors, in the
/// `(name, ok, detail)` shape the other detector selftests use.
pub(super) fn selftest_sampling() -> Vec<(&'static str, bool, String)> {
    let window = 0..CLEAN_RERUN_STRIDE * 8;
    let sampled = |seed_base| -> Vec<u64> {
        window
            .clone()
            .filter(|generation| samples_clean_rerun(seed_base, *generation))
            .collect()
    };
    let first = sampled(0);
    let pure = first == sampled(0);
    // The stride: exactly one generation in every stride window is sampled.
    let one_per_stride = first.len() as u64 == 8
        && first
            .windows(2)
            .all(|pair| pair[1] - pair[0] == CLEAN_RERUN_STRIDE);
    // The offset comes from the campaign seed, so different campaigns sample
    // different generations.
    let offsets: std::collections::BTreeSet<u64> = (0..64u64)
        .filter_map(|seed_base| sampled(seed_base).first().copied())
        .collect();
    vec![
        (
            "clean-rerun-sample-is-pure-in-the-seed",
            pure,
            format!("sampled={first:?}"),
        ),
        (
            "clean-rerun-sample-is-one-per-stride",
            one_per_stride,
            format!("stride={CLEAN_RERUN_STRIDE} sampled={}", first.len()),
        ),
        (
            "clean-rerun-offset-varies-with-the-seed",
            offsets.len() > 1,
            format!("distinct_offsets={}", offsets.len()),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verification_round_trips_through_its_json() {
        let observed = Observation {
            class: CampaignClass::Unclassified,
            signature: Some("UNCLASSIFIED|PLANTED token=#|".into()),
            policy: "bug_depth=1".into(),
            exit: "exit=3".into(),
            finding: Some("PLANTED token=1".into()),
            verdicts: Vec::new(),
            trace: Some("sha256:00".into()),
            replay_diverged: false,
        };
        let mut reproduction = observed.clone();
        reproduction.finding = Some("PLANTED token=2".into());
        reproduction.trace = None;
        reproduction.replay_diverged = true;
        let verification = Verification::judge(VerifyPath::Replay, observed, reproduction);
        assert_eq!(verification.status, VerifyStatus::Nondeterministic);
        assert_eq!(
            Verification::from_json(&verification.to_json()).unwrap(),
            verification
        );
        // A nondeterministic signature is keyed by the OBSERVED outcome alone, so two generations
        // that observed the same failure dedup onto one record.
        {
            let observed = Signature {
                class: CampaignClass::GuestAbort,
                shape: "guest_abort unattributed PLANTED".into(),
                policy: "bug_depth=#".into(),
            };
            let filed = nondeterminism_signature(Some(&observed));
            assert_eq!(filed.class, CampaignClass::Nondeterminism);
            assert!(
                filed.shape.contains(observed.class.as_str())
                    && filed.shape.contains(&observed.shape)
            );
            assert_eq!(filed.policy, observed.policy);
            assert_ne!(filed.key(), nondeterminism_signature(None).key());
        }
    }
}
