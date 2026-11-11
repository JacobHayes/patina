//! A run's outcome: how the guest ended, why the run stopped, and the one
//! class the run is filed under.

use super::*;
use crate::coverage::CodeLocation;
use patina_dst_abi::{Attribution, RunClass};

/// How the guest process ended, structurally. `code` is the guest's own exit
/// status; `signal` is present only when the guest died on a signal, which
/// `code` alone cannot express (it is `128 + signal` there, the same value a
/// guest could have returned deliberately). Reported, never passed through:
/// the tool's own exit status follows the run's class.
pub struct GuestExit {
    pub(super) code: i32,
    pub(super) signal: Option<i32>,
    pub(super) core: bool,
}

/// The portable signal names worth spelling out. A signal outside this set keeps
/// its number and gets no name — a wrong name is worse than none.
pub(super) const SIGNAL_NAMES: &[(i32, &str)] = &[
    (2, "SIGINT"),
    (4, "SIGILL"),
    (5, "SIGTRAP"),
    (6, "SIGABRT"),
    (8, "SIGFPE"),
    (9, "SIGKILL"),
    (11, "SIGSEGV"),
    (13, "SIGPIPE"),
    (15, "SIGTERM"),
];

const SIGKILL: i32 = 9;
/// The terminating signals no instruction raises (SIGHUP, SIGINT, SIGQUIT,
/// SIGTERM). A guest that sends one to itself does so through the virtual
/// kernel, whose default action leaves a stop record; one that arrives
/// without a record was sent from outside the run.
const EXTERNAL_SIGNALS: &[i32] = &[1, 2, 3, 15];

/// Whether every signal a guest sends itself goes through the shim, so one
/// that ends the run without a stop record came from outside. True of the
/// Linux virtual kernel; macOS models `raise` alone, so there an unrecorded
/// signal may still be the guest's own.
const fn guest_signals_are_modeled() -> bool {
    cfg!(target_os = "linux")
}

/// What stopped a run that did not end clean: a stable token for the reason,
/// and the detail that names what was reached and where. The envelope's
/// `stop`.
///
/// The native shim writes one to the supervisor's stop pipe whenever it ends a run
/// (`RunStop`, which its only abort vehicle requires), and the supervisor
/// builds the rest from what only it observes: a pre-run refusal, a verdict
/// the guest reported, a recording it could not commit, the status the guest
/// process ended with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stop {
    pub(crate) reason: String,
    pub(crate) detail: String,
    /// The exit status the guest itself reached, when the stop replaced it.
    pub(crate) guest_exit_code: Option<i32>,
    /// For a mismatch the supervisor judged, which of the run's inputs differs.
    pub(crate) mismatch: Option<&'static str>,
    /// For a compute stop, where the stopped thread was spinning, named from
    /// the executable; absent when no PC was sampled or the binary names no
    /// function there.
    pub(crate) location: Option<CodeLocation>,
    /// On a machine of several processes, the processes the stop is about
    /// (the one that stopped, or every process a deadlock holds), by pid.
    pub(crate) processes: Vec<u64>,
}

/// A stop's `location` as JSON: `{function, file?, line?}`.
pub(crate) fn location_json(location: &CodeLocation) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    fields.insert("function".into(), location.function.clone().into());
    if let Some(file) = &location.file {
        fields.insert("file".into(), file.clone().into());
    }
    if let Some(line) = location.line {
        fields.insert("line".into(), line.into());
    }
    serde_json::Value::Object(fields)
}

/// The `location` of the stop object `stop`, read back.
fn location_of(stop: &serde_json::Value) -> Option<CodeLocation> {
    let location = stop.get("location")?;
    Some(CodeLocation {
        function: location.get("function")?.as_str()?.to_owned(),
        file: location
            .get("file")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        line: location
            .get("line")
            .and_then(serde_json::Value::as_u64)
            .and_then(|line| u32::try_from(line).ok()),
    })
}

impl std::fmt::Display for CodeLocation {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.function)?;
        match (&self.file, self.line) {
            (Some(file), Some(line)) => write!(out, " ({file}:{line})"),
            (Some(file), None) => write!(out, " ({file})"),
            _ => Ok(()),
        }
    }
}

impl Stop {
    pub(crate) fn new(reason: &str, detail: impl Into<String>) -> Self {
        Self {
            reason: reason.to_owned(),
            detail: detail.into(),
            guest_exit_code: None,
            mismatch: None,
            location: None,
            processes: Vec::new(),
        }
    }

    /// The `stop` of a run's own envelope, read back by a verb that relays it.
    pub(crate) fn from_envelope(envelope: &serde_json::Value) -> Option<Self> {
        let stop = envelope.get("stop")?;
        let text = |key: &str| {
            stop.get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
        };
        let mut read = Self::new(text("reason"), text("detail"));
        read.guest_exit_code = stop
            .get("guest_exit_code")
            .and_then(serde_json::Value::as_i64)
            .map(|code| code as i32);
        read.location = location_of(stop);
        read.processes = processes_of(stop);
        Some(read)
    }
}

/// The `processes` a stop object names, read back.
fn processes_of(stop: &serde_json::Value) -> Vec<u64> {
    stop.get("processes")
        .and_then(serde_json::Value::as_array)
        .map(|pids| pids.iter().filter_map(serde_json::Value::as_u64).collect())
        .unwrap_or_default()
}

/// The reason of a run the pre-run audit refused: the binary links something
/// Patina does not model, so no guest executed.
pub(crate) const PRERUN_AUDIT_STOP: &str = "prerun_audit";
/// The reason of a replay refused because the trace belongs to another build
/// or corpus, judged by the supervisor before the guest starts.
pub(crate) const TRACE_MISMATCH_STOP: &str = "trace_mismatch";
/// The reason of a run whose recording patina could not commit while the guest
/// itself came through: the scratch file vanished, or the bundle would not
/// validate.
pub(crate) const TRACE_UNAVAILABLE_STOP: &str = "trace_unavailable";
/// The reason of a run patina's own end-of-run finalization failed.
pub(crate) const SHUTDOWN_FAILURE_STOP: &str = "shutdown_failure";
/// The reason of a process that ended badly before the shim reported the
/// runtime installed.
pub(crate) const NO_RUNTIME_STOP: &str = "no_runtime";
/// The reason of a Rust guest that ended with its runtime's status for a
/// panic.
pub(crate) const PANIC_STOP: &str = "panic";
const RUST_PANIC_STATUS: i32 = 101;
/// The reason of a run the host killed (SIGKILL: the OOM killer, a cgroup
/// limit, an operator), which no guest can do to itself.
pub(crate) const HOST_KILL_STOP: &str = "host_kill";

/// One run's outcome: its class, and what stopped it when it did not end
/// clean. The class carries the attribution and the tool's exit status
/// ([`RunClass::attribution`], [`RunClass::exit_code`]), so an outcome cannot
/// be built without either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub(crate) class: RunClass,
    pub(crate) stop: Option<Stop>,
    /// Whether the run's recording is unusable although the class is the
    /// guest's own: patina's recorder gave out on a run the guest had already
    /// failed, so the finding stands and its trace does not.
    pub(crate) trace_unusable: bool,
}

impl Outcome {
    pub(crate) fn ok() -> Self {
        Self::of(RunClass::Ok, None)
    }

    pub(crate) fn of(class: RunClass, stop: Option<Stop>) -> Self {
        Self {
            class,
            stop,
            trace_unusable: false,
        }
    }

    /// The one line a reader is told first: whose move it is, the class, and
    /// what stopped the run.
    pub(crate) fn headline(&self, guest_exit: Option<&GuestExit>) -> Option<String> {
        let attribution = self.class.attribution()?;
        let lead = match attribution {
            Attribution::Guest => "FINDING in the guest",
            Attribution::PatinaUnsupported => "NOT SUPPORTED by Patina",
            Attribution::PatinaInternal => "INTERNAL ERROR in Patina",
            Attribution::Request => "cannot do this as asked",
        };
        let mut line = format!("patina: {lead} [{}]", self.class);
        if let Some(stop) = &self.stop
            && !stop.detail.is_empty()
        {
            line.push_str(": ");
            line.push_str(stop.detail.lines().next().unwrap_or_default());
        }
        if let Some(exit) = guest_exit {
            let ended = match exit.signal {
                Some(signal) => match SIGNAL_NAMES.iter().find(|(number, _)| *number == signal) {
                    Some((_, name)) => format!("guest killed by {name}"),
                    None => format!("guest killed by signal {signal}"),
                },
                None => format!("guest exit {}", exit.code),
            };
            line.push_str(&format!(" ({ended})"));
        }
        if let Some(location) = self.stop.as_ref().and_then(|stop| stop.location.as_ref()) {
            line.push_str(&format!("\npatina: stopped in {location}"));
        }
        line.push_str(match attribution {
            Attribution::Guest => "",
            Attribution::PatinaUnsupported => {
                "\npatina: the guest reached something Patina does not model; this is not evidence \
                 of a bug in the guest"
            }
            Attribution::PatinaInternal => {
                "\npatina: this is a failure of Patina or of the host, not a finding in the \
                 guest; please report it with this output: \
                 https://github.com/JacobHayes/patina/issues"
            }
            Attribution::Request => "",
        });
        Some(line)
    }
}

/// Everything a finished run left to judge it by.
pub(super) struct RunEvidence<'a> {
    /// The guest's exit status (`128 + signal` for a signal death).
    pub(super) exit_code: i32,
    /// The signal the guest died on, when it died on one.
    pub(super) signal: Option<i32>,
    /// The run's merged `patina.runfacts` document, its `stop` included.
    pub(super) facts: Option<&'a serde_json::Value>,
    /// Whether the supervisor's crash-restart replay left its recording.
    pub(super) crash_replay_diverged: bool,
    /// Whether the run's crash point was reached and the supervisor found
    /// the crash was not carried out, whatever the incarnation died of.
    pub(super) crash_failed: bool,
    /// Whether the shim reported the runtime installed. A process that ends
    /// badly without it never ran the guest under patina.
    pub(super) runtime_started: bool,
    /// What the supervisor could not read off patina's own channels.
    pub(super) channel_defect: Option<&'a str>,
    /// The supervisor could not commit the run's recording, for a reason of
    /// patina's own rather than because the guest died mid-record.
    pub(super) trace_lost: Option<&'a str>,
    /// Whether Rust's runtime starts the guest: a fact of the binary, read
    /// from its symbols.
    pub(super) rust_program: bool,
    /// The recorder dropped the run's recording for outgrowing the trace
    /// budget. Never a reason for a class: recording is write-only, so the
    /// run is what it would have been unrecorded.
    pub(super) trace_abandoned: bool,
}

/// Classify a finished run. Total: every run lands in exactly one
/// [`RunClass`], from structured evidence alone — the runtime's facts
/// document, the shim's stop record, and what the supervisor observed of the
/// process and its binary. Nothing here reads the run's text.
///
/// The order is the precedence. A replay that left its trace is judged first,
/// since nothing after the divergence describes the recorded run. Then the
/// guest's own findings, which a later stop of patina's must not erase. Then
/// the stop the shim named. Then what only the wait status says: a death by
/// signal with no stop record is the guest's own, because the shim cannot
/// abort without leaving one.
pub(super) fn classify(evidence: &RunEvidence<'_>) -> Outcome {
    // Evidence patina could not read leaves the run unjudged: patina's own
    // defect, whatever the rest says.
    if let Some(defect) = evidence.channel_defect {
        return Outcome::of(
            RunClass::Internal,
            Some(Stop::new("channel_defect", defect)),
        );
    }
    let facts = evidence.facts;
    let rows = |key: &str| {
        facts
            .and_then(|facts| facts.get(key))
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
    };
    let text = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let shim_stop = facts.and_then(|facts| facts.get("stop"));
    let shim_detail = shim_stop.map(|stop| text(stop, "detail"));

    let divergence = facts
        .and_then(|facts| facts.get("replay_divergence"))
        .and_then(serde_json::Value::as_str);
    if divergence.is_some() || evidence.crash_replay_diverged {
        let kind = divergence.unwrap_or(CRASH_REPLAY_DIVERGED);
        let detail = match shim_detail.as_deref().filter(|detail| !detail.is_empty()) {
            Some(detail) => format!("the replay left its trace ({kind}): {detail}"),
            None => format!("the replay left its trace ({kind})"),
        };
        return Outcome::of(
            RunClass::Nondeterministic,
            Some(Stop::new("replay_divergence", detail)),
        );
    }

    let findings = rows("runtime_findings");
    let known_limit = |finding: &serde_json::Value| {
        finding
            .get("known_limit")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    };
    if let Some(finding) = findings
        .iter()
        .find(|finding| text(finding, "source") == "liveness" && !known_limit(finding))
    {
        // A child's finding is the run's, attributed to its process.
        let process = finding.get("process").and_then(serde_json::Value::as_u64);
        let mut detail = format!("the liveness watchdog fired: {}", text(finding, "detail"));
        if let Some(pid) = process {
            detail = format!("{detail} (process {pid})");
        }
        let mut stop = Stop::new("liveness", detail);
        stop.processes = process.into_iter().collect();
        return Outcome::of(RunClass::Liveness, Some(stop));
    }
    if let Some(verdict) = rows("verdicts")
        .iter()
        .find(|verdict| text(verdict, "kind") == "violation")
    {
        let mut detail = format!(
            "violation of {:?} {}",
            text(verdict, "label"),
            text(verdict, "detail")
        );
        let process = verdict.get("process").and_then(serde_json::Value::as_u64);
        if let Some(pid) = process {
            detail = format!("{} (process {pid})", detail.trim());
        }
        let mut stop = Stop::new("violation_verdict", detail.trim());
        stop.processes = process.into_iter().collect();
        return Outcome::of(RunClass::Violation, Some(stop));
    }

    // The supervisor's own finding, which the incarnation may not have lived
    // to report: a crash patina could not carry out stopped the guest before
    // it reached a verdict, whatever signal the incarnation then died on.
    if evidence.crash_failed {
        let detail = shim_detail
            .filter(|detail| !detail.is_empty())
            .unwrap_or_else(|| {
                "the run's crash point was reached and the crash could not be carried out"
                    .to_owned()
            });
        return Outcome::of(RunClass::Internal, Some(Stop::new(CRASH_FAILED, detail)));
    }

    if let Some(record) = shim_stop {
        let mut stop = Stop::new(&text(record, "reason"), text(record, "detail"));
        stop.guest_exit_code = record
            .get("guest_exit_code")
            .and_then(serde_json::Value::as_i64)
            .map(|code| code as i32);
        stop.location = location_of(record);
        stop.processes = processes_of(record);
        let Some(class) = RunClass::from_name(&text(record, "class")) else {
            // A stop the supervisor cannot read is a defect in patina's own
            // channel, never the guest's finding.
            stop.detail = format!(
                "the shim stopped the run with an unreadable class {:?}: {}",
                text(record, "class"),
                stop.detail
            );
            return Outcome::of(RunClass::Internal, Some(stop));
        };
        // Patina's end-of-run finalization failing replaces the status of a
        // guest that had already finished. One that had failed on its own
        // keeps that failure as the run's class; only its trace is lost.
        if stop.reason == SHUTDOWN_FAILURE_STOP
            && stop.guest_exit_code.is_some_and(|code| code != 0)
        {
            return Outcome {
                class: RunClass::Failure,
                stop: Some(stop),
                trace_unusable: true,
            };
        }
        return Outcome::of(class, Some(stop));
    }

    if let Some(finding) = findings.iter().find(|finding| known_limit(finding)) {
        return Outcome::of(
            RunClass::Timeout,
            Some(Stop::new("compute_bound", text(finding, "detail"))),
        );
    }

    let clean = evidence.exit_code == 0 && evidence.signal.is_none();
    // A process that ended badly before the shim reported the runtime
    // installed never ran the guest under patina: the loader failed, or the
    // binary carries the shim of another patina, which reports nothing here.
    // Not the guest's finding, whatever status it ended with.
    if !clean && !evidence.runtime_started {
        return Outcome::of(
            RunClass::Internal,
            Some(Stop::new(
                NO_RUNTIME_STOP,
                "the process ended before patina's runtime started in it (it failed to load, \
                 or it was built by another patina: rebuild it with this one)",
            )),
        );
    }
    if let Some(reason) = evidence.trace_lost
        && clean
    {
        return Outcome::of(
            RunClass::Internal,
            Some(Stop::new(
                TRACE_UNAVAILABLE_STOP,
                format!("the run's recording could not be written: {reason}"),
            )),
        );
    }
    let mut outcome = match evidence.signal {
        Some(SIGKILL) => Outcome::of(
            RunClass::Internal,
            Some(Stop::new(
                HOST_KILL_STOP,
                "the guest was killed by SIGKILL from outside the run (the host's out-of-memory \
                 killer, a resource limit or an operator); not a guest failure",
            )),
        ),
        // Not a signal executing code raises: with no stop record it came
        // from outside the run (an operator, a supervising harness).
        Some(signal) if guest_signals_are_modeled() && EXTERNAL_SIGNALS.contains(&signal) => {
            Outcome::of(
                RunClass::Internal,
                Some(Stop::new(
                    HOST_KILL_STOP,
                    format!(
                        "the guest was ended by signal {signal} from outside the run; not a guest \
                     failure"
                    ),
                )),
            )
        }
        Some(signal) => Outcome::of(
            RunClass::Crash,
            Some(Stop::new(
                "signal",
                match SIGNAL_NAMES.iter().find(|(number, _)| *number == signal) {
                    Some((_, name)) => format!("the guest died on {name}"),
                    None => format!("the guest died on signal {signal}"),
                },
            )),
        ),
        // Rust's runtime ends a program with this status when its main
        // thread panics, and a test binary when a test fails. Known from the
        // status and the binary, not from what the guest printed.
        None if evidence.exit_code == RUST_PANIC_STATUS && evidence.rust_program => Outcome::of(
            RunClass::Failure,
            Some(Stop::new(
                PANIC_STOP,
                "the guest panicked, or a test in it failed",
            )),
        ),
        None if evidence.exit_code != 0 => Outcome::of(
            RunClass::Failure,
            Some(Stop::new(
                "exit_status",
                format!("the guest exited with status {}", evidence.exit_code),
            )),
        ),
        None => Outcome::ok(),
    };
    outcome.trace_unusable =
        (evidence.trace_lost.is_some() || evidence.trace_abandoned) && outcome.class.is_failure();
    outcome
}

#[cfg(test)]
mod tests;
