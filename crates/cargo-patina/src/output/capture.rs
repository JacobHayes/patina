//! Guest output and runtime-facts capture.

use super::*;

/// A run's captured (or streamed) result: the exit code plus, when captured, the
/// guest's stdout/stderr bytes. `captured == false` means the streams already
/// went to the terminal (human default) and the byte buffers are empty.
pub struct Captured {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub captured: bool,
    /// The signal that terminated the guest, when it died on one. `exit_code` is
    /// the shell-style `128 + signal` for such a death, which is lossy (a guest
    /// that `exit(134)`s and one killed by `SIGABRT` are indistinguishable); the
    /// envelope's `guest_exit` carries the distinction structurally.
    pub signal: Option<i32>,
    /// Observed OS wait-status core bit, meaningful only when `signal` is set.
    /// This is not inferred from the signal's default disposition.
    pub core: bool,
}

/// End a guest's unfinished last line of captured output, so the line patina
/// appends next is a line of its own rather than the tail of a line the guest
/// left open when it stopped.
pub fn end_guest_line(stream: &mut Vec<u8>) {
    if stream.last().is_some_and(|byte| *byte != b'\n') {
        stream.push(b'\n');
    }
}

/// Whether guest output will be captured (JSON / render / report active).
pub fn capture_active() -> bool {
    options().wants_capture()
}

/// Parse the facts read back off the channel. The runtime appends a complete
/// document at each point the process might die and again at finish, so the
/// LAST complete (newline-terminated) document is the run's state; a torn final
/// line is a write the process did not live to finish and is ignored.
///
/// A process may run several runtime contexts, each writing its own documents (`context`). The run's `verdicts` are every
/// context's latest list, in the order the contexts first wrote, so a later
/// context finishing cleanly cannot erase an earlier one's violation, and a
/// document that carries no verdicts (a compute-bound stop's) does not either.
///
/// A guest that spawned processes writes one stream of documents for its
/// whole machine: a child's are marked with its pid (`process`). The run's
/// state is then the root's last document, with every process's verdicts
/// (kept per process and context as above), each child's latest
/// `runtime_findings` after the root's (each marked with its `process`),
/// each child's latest fault planes and buggify sites added to the root's
/// ([`add_activity`]), and the first `replay_divergence` any process noted;
/// with no document of the root's, the run has none.
///
/// No complete document means the run never got that far — it aborted before
/// finalization — and the envelope says so by omitting the fields (absent,
/// never zero). A complete line that is not a `patina.runfacts` document of
/// this schema is a defect in patina's own channel, or the facts of a guest
/// built with another patina, so it fails closed rather than being quietly
/// dropped.
pub fn parse_facts(bytes: &[u8]) -> Result<Option<serde_json::Value>, CliError> {
    type Key = (Option<u64>, Option<u64>);
    let complete = match bytes.iter().rposition(|byte| *byte == b'\n') {
        Some(end) => &bytes[..end],
        None => return Ok(None),
    };
    let mut root = None;
    let mut verdicts: Vec<(Key, Vec<serde_json::Value>)> = Vec::new();
    let mut findings: Vec<(u64, Vec<serde_json::Value>)> = Vec::new();
    let mut activity: Vec<(u64, serde_json::Value)> = Vec::new();
    let mut divergence = None;
    for line in complete
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        let document = parse_facts_document(line)?;
        let process = document.get("process").and_then(serde_json::Value::as_u64);
        if let Some(list) = document
            .get("verdicts")
            .and_then(serde_json::Value::as_array)
        {
            let context = document.get("context").and_then(serde_json::Value::as_u64);
            // A child's verdict is the run's, attributed to its process.
            let mut list = list.clone();
            if let Some(pid) = process {
                for verdict in &mut list {
                    if let serde_json::Value::Object(verdict) = verdict {
                        verdict.insert("process".into(), pid.into());
                    }
                }
            }
            match verdicts
                .iter_mut()
                .find(|(seen, _)| *seen == (process, context))
            {
                Some(entry) => entry.1 = list,
                None => verdicts.push(((process, context), list)),
            }
        }
        if divergence.is_none() {
            divergence = document.get("replay_divergence").cloned();
        }
        match process {
            Some(pid) => {
                // A child's finding is the run's, attributed to its process.
                let mut list = document
                    .get("runtime_findings")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for finding in &mut list {
                    if let serde_json::Value::Object(finding) = finding {
                        finding.insert("process".into(), pid.into());
                    }
                }
                match findings.iter_mut().find(|(seen, _)| *seen == pid) {
                    Some(entry) => entry.1 = list,
                    None => findings.push((pid, list)),
                }
                match activity.iter_mut().find(|(seen, _)| *seen == pid) {
                    Some(entry) => entry.1 = document.clone(),
                    None => activity.push((pid, document.clone())),
                }
            }
            None => root = Some(document),
        }
    }
    // A child's document never stands for the run's: a root that wrote
    // none leaves the run without facts, as a single process would.
    let Some(mut last) = root else {
        return Ok(None);
    };
    let merged: Vec<serde_json::Value> = verdicts.into_iter().flat_map(|(_, list)| list).collect();
    if let serde_json::Value::Object(document) = &mut last {
        document.remove("process");
        document.remove("verdicts");
        if !merged.is_empty() {
            document.insert("verdicts".into(), serde_json::Value::Array(merged));
        }
        if let Some(divergence) = divergence {
            document.entry("replay_divergence").or_insert(divergence);
        }
        let children: Vec<serde_json::Value> =
            findings.into_iter().flat_map(|(_, list)| list).collect();
        if !children.is_empty()
            && let serde_json::Value::Array(list) = document
                .entry("runtime_findings")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        {
            list.extend(children);
        }
        for (pid, child) in &activity {
            add_activity(document, *pid, child);
        }
    }
    Ok(Some(last))
}

/// Add child `pid`'s activity, its latest facts document `child`, to the
/// run's `document`: each fault plane's counts (`fault_reports`, but the
/// exploration planes, which are each process's own scheduler's) and its
/// buggify sites (`sdk`), so a fault or a site that landed only in a child
/// is the run's, and a plane is vacuous only where every process left it
/// so.
fn add_activity(
    document: &mut serde_json::Map<String, serde_json::Value>,
    pid: u64,
    child: &serde_json::Value,
) {
    use serde_json::Value;
    if let Some(Value::Object(planes)) = child.get("fault_reports") {
        let run = document
            .entry("fault_reports")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Value::Object(run) = run {
            for (name, plane) in planes {
                if matches!(name.as_str(), "schedule" | "swarm") {
                    continue;
                }
                match run.get_mut(name) {
                    Some(existing) => {
                        add_counts(existing, plane);
                        judge_vacuity(existing);
                    }
                    None => {
                        run.insert(name.clone(), plane.clone());
                    }
                }
            }
        }
    }
    let Some(Value::Object(sdk)) = child.get("sdk") else {
        return;
    };
    // A child's sites are its own: each says which process it is.
    let mut sdk = sdk.clone();
    for list in ["declared_sites", "sites"] {
        if let Some(Value::Array(sites)) = sdk.get_mut(list) {
            for site in sites {
                if let Value::Object(site) = site {
                    site.insert("process".into(), pid.into());
                }
            }
        }
    }
    let Some(Value::Object(run)) = document.get_mut("sdk") else {
        document.insert("sdk".into(), Value::Object(sdk));
        return;
    };
    for count in [
        "sites_registered",
        "sites_activated",
        "total_firings",
        "cutoff_suppressed",
    ] {
        let sum = [run.get(count), sdk.get(count)]
            .into_iter()
            .flatten()
            .filter_map(Value::as_u64)
            .sum::<u64>();
        run.insert(count.into(), sum.into());
    }
    for flag in ["enabled", "cutoff_reached"] {
        let either = [run.get(flag), sdk.get(flag)]
            .into_iter()
            .flatten()
            .any(|value| value.as_bool() == Some(true));
        run.insert(flag.into(), either.into());
    }
    for list in ["declared_sites", "sites"] {
        if let Some(Value::Array(sites)) = sdk.remove(list)
            && let Value::Array(run) = run.entry(list).or_insert_with(|| Value::Array(Vec::new()))
        {
            run.extend(sites);
        }
    }
}

/// Add `other`'s counts to `into`, both one plane of a fault report:
/// numbers sum (an object of them, key by key), but `targets_missed`, a
/// target every process has missed, is the least; a flag holds where
/// either says so (`vacuous` is judged again from the sums, by
/// [`judge_vacuity`]).
fn add_counts(into: &mut serde_json::Value, other: &serde_json::Value) {
    use serde_json::Value;
    let (Value::Object(into), Value::Object(other)) = (into, other) else {
        return;
    };
    for (key, value) in other {
        let Some(existing) = into.get_mut(key) else {
            into.insert(key.clone(), value.clone());
            continue;
        };
        match (&*existing, value) {
            (Value::Number(a), Value::Number(b)) => {
                if let (Some(a), Some(b)) = (a.as_u64(), b.as_u64()) {
                    *existing = if key == "targets_missed" {
                        a.min(b)
                    } else {
                        a + b
                    }
                    .into();
                }
            }
            (Value::Bool(a), Value::Bool(b)) => *existing = (*a || *b).into(),
            (Value::Object(_), Value::Object(_)) => add_counts(existing, value),
            _ => {}
        }
    }
}

/// Each fault class's `<class>_vacuity_diagnosable` flag (armed and given
/// traffic) and the count of its faults that landed, as the runtime's
/// fault reports pair them.
const FAULT_CLASSES: &[(&str, &str)] = &[
    ("error_vacuity_diagnosable", "errors_injected"),
    ("short_vacuity_diagnosable", "shorts_applied"),
    ("latency_vacuity_diagnosable", "latency_applied"),
    ("fail_vacuity_diagnosable", "failures_injected"),
    ("jump_vacuity_diagnosable", "jumps_applied"),
    ("drop_vacuity_diagnosable", "drops_applied"),
    ("jitter_vacuity_diagnosable", "jitter_applied"),
    ("duplicate_vacuity_diagnosable", "duplicates_applied"),
    ("connect_refuse_vacuity_diagnosable", "connects_refused"),
    ("reset_vacuity_diagnosable", "resets_injected"),
    ("partition_vacuity_diagnosable", "partition_blocks"),
];

/// Judge a merged fault plane's `vacuous` as the runtime judges one
/// process's: a target missed, or a class armed and given traffic of which
/// no fault landed, in any process.
fn judge_vacuity(plane: &mut serde_json::Value) {
    let serde_json::Value::Object(plane) = plane else {
        return;
    };
    if !plane.contains_key("vacuous") {
        return;
    }
    let count = |key: &str| plane.get(key).and_then(serde_json::Value::as_u64);
    let vacuous = count("targets_missed").is_some_and(|missed| missed != 0)
        || FAULT_CLASSES.iter().any(|(armed, landed)| {
            plane.get(*armed).and_then(serde_json::Value::as_bool) == Some(true)
                && count(landed) == Some(0)
        });
    plane.insert("vacuous".into(), vacuous.into());
}

/// What the shim said on the stop pipe.
#[derive(Debug, Default, PartialEq)]
pub struct StopChannel {
    /// The runtime was installed: the guest ran under patina.
    pub started: bool,
    /// Why the shim ended the run (`RunStop`), as the `stop` object the run is
    /// judged by; `None` when the shim ended nothing.
    pub stop: Option<serde_json::Value>,
}

/// Read the stop pipe back: whether the runtime started, and the shim's stop
/// record if it ended the run. The first stop stands, since a second can only
/// be a consequence of the first. Bytes that are not records of this schema
/// are a defect in patina's own channel, or the records of a guest built
/// with another patina, and are refused rather than read as "no stop".
pub fn parse_stop(bytes: &[u8]) -> Result<StopChannel, CliError> {
    let unreadable = |what: String| {
        CliError(format!(
            "the stop pipe carried {what}; expected {} records. A guest built by another \
             patina carries its own shim: rebuild it with this one",
            patina_dst_runtime::STOP_SCHEMA
        ))
    };
    let mut channel = StopChannel::default();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        let mut record: serde_json::Value = serde_json::from_slice(line).map_err(|error| {
            unreadable(format!("{} bytes that are not JSON ({error})", line.len()))
        })?;
        if record.get("schema").and_then(serde_json::Value::as_str)
            != Some(patina_dst_runtime::STOP_SCHEMA)
        {
            return Err(unreadable(format!("schema {:?}", record.get("schema"))));
        }
        if record.get("started").and_then(serde_json::Value::as_bool) == Some(true) {
            channel.started = true;
        } else if let Some(stop) = record
            .get_mut("stop")
            .map(serde_json::Value::take)
            .filter(serde_json::Value::is_object)
        {
            channel.stop.get_or_insert(stop);
        } else {
            return Err(unreadable("a record that says nothing".to_string()));
        }
    }
    Ok(channel)
}

fn parse_facts_document(line: &[u8]) -> Result<serde_json::Value, CliError> {
    let value: serde_json::Value = serde_json::from_slice(line).map_err(|error| {
        CliError(format!(
            "the run-facts channel carried {} bytes that are not JSON: {error}",
            line.len()
        ))
    })?;
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some(schema) if schema == patina_dst_runtime::FACTS_SCHEMA => Ok(value),
        other => Err(CliError(format!(
            "the run-facts channel carried schema {other:?}; expected {}. A guest built by \
             another patina carries its own shim: rebuild it with this one",
            patina_dst_runtime::FACTS_SCHEMA
        ))),
    }
}

#[cfg(test)]
mod tests;
