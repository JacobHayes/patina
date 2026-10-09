//! Machine-readable result envelope serialization.

use super::*;

/// A machine-readable result envelope. Fields absent for a given verb are
/// omitted from the JSON. Documented in `llms.txt` and `TUTORIAL.md`.
pub struct Envelope {
    verb: String,
    result: String,
    exit_code: i32,
    pub(crate) family: Option<String>,
    pub(crate) artifact: Option<String>,
    pub(super) fingerprint: Option<String>,
    pub(super) seed: Option<u64>,
    pub(crate) trace: Option<TraceFacts>,
    pub(super) coverage: Option<CoverageReport>,
    pub(super) depth: Option<DepthReport>,
    pub(super) render: Option<String>,
    /// audit findings / build outputs / mismatch detail — a list of strings.
    pub(crate) findings: Vec<String>,
    /// Structured audit finding details; additive companion to `findings`.
    pub(crate) finding_details: Vec<serde_json::Value>,
    pub(crate) output_path: Option<String>,
    pub(crate) content_hash: Option<String>,
    /// Guest verdicts reported through the verdict ABI, in call order. Additive:
    /// omitted entirely when the run reported none.
    pub(super) verdicts: Vec<VerdictFact>,
    pub(super) markers: Vec<String>,
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
    /// Native crash-restart facts, if the supervisor performed a modeled restart.
    pub(super) crash_restart: Option<serde_json::Value>,
    /// Patina's own fail-closed refusal, when patina refused. Absent on a guest's
    /// own abort.
    pub(crate) refusal: Option<Refusal>,
    /// How the guest process ended (exit code, terminating signal).
    pub(super) guest_exit: Option<GuestExit>,
    pub(super) stdout: Option<String>,
    pub(super) stderr: Option<String>,
    pub(crate) message: Option<String>,
    config: Option<serde_json::Value>,
}

impl Envelope {
    pub fn new(verb: &str, result: &str, exit_code: i32) -> Self {
        Self {
            verb: verb.to_string(),
            result: result.to_string(),
            exit_code,
            family: None,
            artifact: None,
            fingerprint: None,
            seed: None,
            trace: None,
            coverage: None,
            depth: None,
            render: None,
            findings: Vec::new(),
            finding_details: Vec::new(),
            output_path: None,
            content_hash: None,
            verdicts: Vec::new(),
            markers: Vec::new(),
            result_line: None,
            fault_reports: None,
            runtime_findings: Vec::new(),
            cpu_charges: None,
            crash_restart: None,
            refusal: None,
            guest_exit: None,
            stdout: None,
            stderr: None,
            message: None,
            config: config::provenance_json(),
        }
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        use serde_json::{Map, Value};
        let mut m = Map::new();
        m.insert("schema".into(), Value::from(ENVELOPE_SCHEMA));
        m.insert("verb".into(), Value::from(self.verb.clone()));
        m.insert("result".into(), Value::from(self.result.clone()));
        m.insert("exit_code".into(), Value::from(self.exit_code));
        if let Some(v) = &self.family {
            m.insert("family".into(), Value::from(v.clone()));
        }
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
        if let Some(d) = &self.depth {
            let mut dm = Map::new();
            dm.insert("family".into(), Value::from(d.family.clone()));
            dm.insert("fuel_consumed".into(), Value::from(d.fuel_consumed));
            dm.insert("hostcalls_total".into(), Value::from(d.hostcalls_total()));
            let mut hm = Map::new();
            for (name, count) in &d.hostcalls {
                hm.insert(name.clone(), Value::from(*count));
            }
            dm.insert("hostcalls".into(), Value::Object(hm));
            m.insert("depth".into(), Value::Object(dm));
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
        if !self.verdicts.is_empty() {
            let rows: Vec<Value> = self
                .verdicts
                .iter()
                .map(|verdict| {
                    let mut vm = Map::new();
                    vm.insert("seq".into(), Value::from(verdict.seq));
                    vm.insert("kind".into(), Value::from(verdict.kind.as_str()));
                    vm.insert("label".into(), Value::from(verdict.label.clone()));
                    vm.insert("detail".into(), Value::from(verdict.detail.clone()));
                    Value::Object(vm)
                })
                .collect();
            m.insert("verdicts".into(), Value::Array(rows));
        }
        if !self.markers.is_empty() {
            m.insert("markers".into(), Value::from(self.markers.clone()));
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
        if let Some(v) = &self.crash_restart {
            m.insert("crash_restart".into(), v.clone());
        }
        if let Some(v) = &self.refusal {
            let mut rm = Map::new();
            rm.insert("class".into(), Value::from(v.class.clone()));
            rm.insert("message".into(), Value::from(v.message.clone()));
            if let Some(code) = v.guest_exit_code {
                rm.insert("guest_exit_code".into(), Value::from(code));
            }
            m.insert("refusal".into(), Value::Object(rm));
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
        if let Some(v) = &self.config {
            m.insert("config".into(), v.clone());
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
