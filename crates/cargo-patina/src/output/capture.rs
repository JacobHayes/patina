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

/// Run a fully-configured child command, capturing its output when the installed
/// options require it (JSON / render / report) and otherwise inheriting the
/// caller's streams unchanged (the human default). Signal death maps to a
/// `CliError` exactly like [`crate::exit_code`].
/// Whether guest output will be captured (JSON / render / report active and not
/// suppressed). Exposed so callers that must run the child themselves (e.g. the
/// starvation stall backstop's kill-able wait loop) can mirror
/// [`execute_command`]'s capture semantics exactly.
pub fn capture_active() -> bool {
    options().wants_capture() && !suppressed()
}

/// Whether this invocation wants the runtime's structured `patina.runfacts/v1`
/// document. Only the JSON envelope consumes it, so a human run installs no
/// channel at all and the guest is byte-for-byte unaffected.
pub fn facts_active() -> bool {
    options().is_json() && !suppressed()
}

/// Parse a facts document read back off the channel.
///
/// An empty channel means the run never wrote one — it aborted before
/// finalization, or this family does not carry the channel — and the envelope
/// says so by omitting the fields (absent, never zero). Anything else that is
/// not a `patina.runfacts/v1` document is a defect in patina's own channel, so
/// it fails closed rather than being quietly dropped.
pub fn parse_facts(bytes: &[u8]) -> Result<Option<serde_json::Value>, CliError> {
    if bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(None);
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        CliError(format!(
            "the run-facts channel carried {} bytes that are not JSON: {error}",
            bytes.len()
        ))
    })?;
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some(schema) if schema == patina_dst_runtime::FACTS_SCHEMA => Ok(Some(value)),
        other => Err(CliError(format!(
            "the run-facts channel carried schema {other:?}; expected {}",
            patina_dst_runtime::FACTS_SCHEMA
        ))),
    }
}

pub fn execute_command(command: &mut Command) -> Result<Captured, CliError> {
    if capture_active() {
        let output = command
            .output()
            .map_err(|error| CliError(format!("failed to execute child process: {error}")))?;
        Ok(Captured {
            exit_code: exit_code(output.status)?,
            stdout: output.stdout,
            stderr: output.stderr,
            captured: true,
            signal: None,
            core: false,
        })
    } else {
        let status: ExitStatus = command
            .status()
            .map_err(|error| CliError(format!("failed to execute child process: {error}")))?;
        Ok(Captured {
            exit_code: exit_code(status)?,
            stdout: Vec::new(),
            stderr: Vec::new(),
            captured: false,
            signal: None,
            core: false,
        })
    }
}

#[cfg(test)]
mod tests;
