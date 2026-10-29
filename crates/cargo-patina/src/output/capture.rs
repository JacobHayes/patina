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

/// Whether this invocation emits a JSON envelope (and so answers a refused
/// run with one rather than with an error).
pub fn json_active() -> bool {
    options().is_json()
}

/// Whether this invocation wants the runtime's structured `patina.runfacts/v1`
/// document: whenever the run's outcome is classified (the JSON envelope, a
/// render or failure report). A plain human run installs no channel at all and
/// the guest is byte-for-byte unaffected.
pub fn facts_active() -> bool {
    capture_active()
}

/// Parse the facts read back off the channel. The runtime appends a complete
/// document at each point the process might die and again at finish, so the
/// LAST complete (newline-terminated) document is the run's state; a torn final
/// line is a write the process did not live to finish and is ignored.
///
/// A process may run several runtime contexts (a cargo-family test binary),
/// each writing its own documents (`context`). The run's `verdicts` are every
/// context's latest list, in the order the contexts first wrote, so a later
/// context finishing cleanly cannot erase an earlier one's violation, and a
/// document that carries no verdicts (a compute-bound stop's) does not either.
///
/// No complete document means the run never got that far — it aborted before
/// finalization, or this family does not carry the channel — and the envelope
/// says so by omitting the fields (absent, never zero). A complete line that is
/// not a `patina.runfacts/v1` document is a defect in patina's own channel, so
/// it fails closed rather than being quietly dropped.
pub fn parse_facts(bytes: &[u8]) -> Result<Option<serde_json::Value>, CliError> {
    let complete = match bytes.iter().rposition(|byte| *byte == b'\n') {
        Some(end) => &bytes[..end],
        None => return Ok(None),
    };
    let mut last = None;
    let mut verdicts: Vec<(Option<u64>, Vec<serde_json::Value>)> = Vec::new();
    for line in complete
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        let document = parse_facts_document(line)?;
        if let Some(list) = document
            .get("verdicts")
            .and_then(serde_json::Value::as_array)
        {
            let context = document.get("context").and_then(serde_json::Value::as_u64);
            match verdicts.iter_mut().find(|(seen, _)| *seen == context) {
                Some(entry) => entry.1 = list.clone(),
                None => verdicts.push((context, list.clone())),
            }
        }
        last = Some(document);
    }
    let Some(mut last) = last else {
        return Ok(None);
    };
    let merged: Vec<serde_json::Value> = verdicts.into_iter().flat_map(|(_, list)| list).collect();
    if let serde_json::Value::Object(root) = &mut last {
        root.remove("verdicts");
        if !merged.is_empty() {
            root.insert("verdicts".into(), serde_json::Value::Array(merged));
        }
    }
    Ok(Some(last))
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
            "the run-facts channel carried schema {other:?}; expected {}",
            patina_dst_runtime::FACTS_SCHEMA
        ))),
    }
}

#[cfg(test)]
mod tests;
