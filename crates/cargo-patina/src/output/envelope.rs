//! Machine-readable result envelope serialization.

use super::*;
use patina_dst_abi::RunClass;

/// The `crash_restart.terminal_outcome.kind` of a crash-restart replay that
/// departed from its recording at or before the crash, so incarnation 1 never
/// ran.
pub const CRASH_REPLAY_DIVERGED: &str = "replay_diverged";

/// The `crash_restart.terminal_outcome.kind` of a run whose crash point was
/// reached and whose crash the supervisor found was not carried out.
pub const CRASH_FAILED: &str = "crash_failed";

/// A machine-readable result envelope. Fields absent for a given verb are
/// omitted from the JSON. Documented in `llms.txt` and `TUTORIAL.md`.
///
/// `result` is the outcome's one class ([`RunClass`]); `attribution` and
/// `exit_code` are derived from it, so an envelope cannot name a class
/// without both, and `exit_code` is the tool's own exit status, never the
/// guest's (`guest_exit`).
pub struct Envelope {
    verb: String,
    result: RunClass,
    pub(crate) artifact: Option<String>,
    pub(super) fingerprint: Option<String>,
    pub(super) seed: Option<u64>,
    pub(crate) trace: Option<TraceFacts>,
    pub(super) coverage: Option<CoverageReport>,
    pub(super) render: Option<String>,
    /// audit findings / build outputs / mismatch detail — a list of strings.
    pub(crate) findings: Vec<String>,
    /// Structured audit finding details; additive companion to `findings`.
    pub(crate) finding_details: Vec<serde_json::Value>,
    pub(crate) output_path: Option<String>,
    pub(crate) content_hash: Option<String>,
    /// Guest verdicts reported through the verdict ABI, in call order
    /// (`patina.runfacts/v1`'s `verdicts`). Omitted when the run reported none.
    pub(super) verdicts: Option<serde_json::Value>,
    /// The cooperative-SUT site counters (`patina.runfacts/v1`'s `sdk`).
    pub(super) sdk: Option<serde_json::Value>,
    /// The exploration-policy accounting and bug-depth estimate
    /// (`patina.runfacts/v1`'s `schedule_policy`).
    pub(super) schedule_policy: Option<serde_json::Value>,
    pub(super) result_line: Option<String>,
    /// Runtime-owned per-plane fault accounting (`patina.runfacts/v1`'s
    /// `fault_reports`), carried through verbatim.
    pub(super) fault_reports: Option<serde_json::Value>,
    /// Runtime-detected findings with a `source` attribution (liveness/converge
    /// watchdog, schedule diagnostics).
    pub(super) runtime_findings: Vec<serde_json::Value>,
    /// The CPU time the run's guest calls were charged, per task
    /// (`patina.runfacts/v1`'s `cpu_charges`), carried through verbatim.
    pub(super) cpu_charges: Option<serde_json::Value>,
    /// The kind of replay divergence the trace layer reported
    /// (`patina.runfacts/v1`'s `replay_divergence`): the replay did not follow
    /// its trace. Lifted from the facts channel, which the guest cannot write,
    /// never from the run's text.
    pub(super) replay_divergence: Option<String>,
    /// Native crash-restart facts, if the supervisor performed a modeled
    /// restart. `terminal_outcome.kind` is [`CRASH_REPLAY_DIVERGED`] for a
    /// replay that departed from its recording at or before the crash.
    pub(super) crash_restart: Option<serde_json::Value>,
    /// Operator-accepted relaxations that qualify the run's determinism.
    pub(super) qualifications: Vec<Qualification>,
    /// What stopped a run that did not end clean: the reason's token and the
    /// detail that names what was reached.
    pub(crate) stop: Option<Stop>,
    /// The run's recording is unusable although its class is the guest's own.
    pub(crate) trace_unusable: bool,
    /// How the guest process ended (exit code, terminating signal).
    pub(super) guest_exit: Option<GuestExit>,
    /// `guest_exit` as a child run's own envelope reported it, for a verb that
    /// relays the run that decided its result (`test`).
    pub(super) guest_exit_raw: Option<serde_json::Value>,
    pub(super) stdout: Option<String>,
    pub(super) stderr: Option<String>,
    pub(crate) message: Option<String>,
}

impl Envelope {
    pub fn new(verb: &str, result: RunClass) -> Self {
        Self {
            verb: verb.to_string(),
            result,
            artifact: None,
            fingerprint: None,
            seed: None,
            trace: None,
            coverage: None,
            render: None,
            findings: Vec::new(),
            finding_details: Vec::new(),
            output_path: None,
            content_hash: None,
            verdicts: None,
            sdk: None,
            schedule_policy: None,
            result_line: None,
            fault_reports: None,
            runtime_findings: Vec::new(),
            cpu_charges: None,
            replay_divergence: None,
            crash_restart: None,
            qualifications: Vec::new(),
            stop: None,
            trace_unusable: false,
            guest_exit: None,
            guest_exit_raw: None,
            stdout: None,
            stderr: None,
            message: None,
        }
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        use serde_json::{Map, Value};
        let mut m = Map::new();
        m.insert("schema".into(), Value::from(ENVELOPE_SCHEMA));
        m.insert("verb".into(), Value::from(self.verb.clone()));
        m.insert("result".into(), Value::from(self.result.as_str()));
        if let Some(attribution) = self.result.attribution() {
            m.insert("attribution".into(), Value::from(attribution.as_str()));
        }
        m.insert("exit_code".into(), Value::from(self.result.exit_code()));
        if let Some(v) = &self.artifact {
            m.insert("artifact".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.fingerprint {
            m.insert("fingerprint".into(), Value::from(v.clone()));
        }
        if let Some(v) = self.seed {
            m.insert("seed".into(), Value::from(v));
        }
        if let Some(t) = &self.trace {
            let mut tm = Map::new();
            tm.insert("path".into(), Value::from(t.path.clone()));
            tm.insert("format_version".into(), Value::from(t.format_version));
            tm.insert("timelines".into(), Value::from(t.timelines.clone()));
            tm.insert("event_count".into(), Value::from(t.event_count));
            tm.insert("metadata".into(), t.metadata.clone());
            m.insert("trace".into(), Value::Object(tm));
        }
        if let Some(c) = &self.coverage {
            let mut cm = Map::new();
            cm.insert("edges_total".into(), Value::from(c.edges_total));
            cm.insert("edges_covered".into(), Value::from(c.edges_covered));
            cm.insert("covered_permille".into(), Value::from(c.covered_permille));
            cm.insert("hits_total".into(), Value::from(c.hits_total));
            cm.insert("hits_max".into(), Value::from(c.hits_max));
            cm.insert("saturated".into(), Value::from(c.saturated));
            if let Some(path) = &c.map_path {
                cm.insert(
                    "map_path".into(),
                    Value::from(path.to_string_lossy().into_owned()),
                );
            }
            m.insert("coverage".into(), Value::Object(cm));
        }
        if let Some(v) = &self.render {
            m.insert("render".into(), Value::from(v.clone()));
        }
        if !self.findings.is_empty() {
            m.insert("findings".into(), Value::from(self.findings.clone()));
        }
        if !self.finding_details.is_empty() {
            m.insert(
                "finding_details".into(),
                Value::from(self.finding_details.clone()),
            );
        }
        if let Some(v) = &self.output_path {
            m.insert("output_path".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.content_hash {
            m.insert("content_hash".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.verdicts {
            m.insert("verdicts".into(), v.clone());
        }
        if let Some(v) = &self.sdk {
            m.insert("sdk".into(), v.clone());
        }
        if let Some(v) = &self.schedule_policy {
            m.insert("schedule_policy".into(), v.clone());
        }
        if let Some(v) = &self.result_line {
            m.insert("result_line".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.fault_reports {
            m.insert("fault_reports".into(), v.clone());
        }
        if !self.runtime_findings.is_empty() {
            m.insert(
                "runtime_findings".into(),
                Value::Array(self.runtime_findings.clone()),
            );
        }
        if let Some(v) = &self.cpu_charges {
            m.insert("cpu_charges".into(), v.clone());
        }
        if let Some(v) = &self.replay_divergence {
            m.insert("replay_divergence".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.crash_restart {
            m.insert("crash_restart".into(), v.clone());
        }
        if !self.qualifications.is_empty() {
            let rows: Vec<Value> = self
                .qualifications
                .iter()
                .map(|qualification| {
                    let mut qm = Map::new();
                    qm.insert("kind".into(), Value::from(qualification.kind));
                    qm.insert("detail".into(), Value::from(qualification.detail.clone()));
                    Value::Object(qm)
                })
                .collect();
            m.insert("qualifications".into(), Value::Array(rows));
        }
        if let Some(v) = &self.stop {
            let mut rm = Map::new();
            rm.insert("reason".into(), Value::from(v.reason.clone()));
            rm.insert("detail".into(), Value::from(v.detail.clone()));
            if let Some(code) = v.guest_exit_code {
                rm.insert("guest_exit_code".into(), Value::from(code));
            }
            if let Some(mismatch) = v.mismatch {
                rm.insert("mismatch".into(), Value::from(mismatch));
            }
            m.insert("stop".into(), Value::Object(rm));
        }
        if self.trace_unusable {
            m.insert("trace_unusable".into(), Value::from(true));
        }
        if let Some(v) = &self.guest_exit {
            let mut gm = Map::new();
            gm.insert("code".into(), Value::from(v.code));
            if let Some(signal) = v.signal {
                gm.insert("signal".into(), Value::from(signal));
                gm.insert("core".into(), Value::from(v.core));
                if let Some((_, name)) = SIGNAL_NAMES.iter().find(|(n, _)| *n == signal) {
                    gm.insert("signal_name".into(), Value::from(*name));
                }
            }
            m.insert("guest_exit".into(), Value::Object(gm));
        } else if let Some(v) = &self.guest_exit_raw {
            m.insert("guest_exit".into(), v.clone());
        }
        if let Some(v) = &self.stdout {
            m.insert("stdout".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.stderr {
            m.insert("stderr".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.message {
            m.insert("message".into(), Value::from(v.clone()));
        }
        Value::Object(m)
    }

    /// Print the envelope as one line of JSON to stdout.
    pub fn emit(&self) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{}", self.to_json());
    }
}

#[cfg(test)]
mod tests;
