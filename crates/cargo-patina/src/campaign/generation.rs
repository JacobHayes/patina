//! Child generation execution, result envelopes, and timeout containment.

use super::{FindingFacts, GenerationFacts, RunFacts, VerdictFacts, recognize_verdicts};
use crate::CliError;
use std::path::Path;
use std::process::Command;

/// A host-side kill. SIGKILL is the one death a guest cannot inflict on itself:
/// it cannot be raised by `abort()`, caught, blocked, or handled, so a generation
/// that died on it was killed from OUTSIDE — the kernel OOM killer, a cgroup
/// limit, an operator, or this campaign's own timeout backstop. Never a finding.
pub(super) const SIGKILL: i32 = 9;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

/// One generation's completed run: the structured facts the classifier reads,
/// plus the child's captured streams for the folds that parse their own report
/// lines (`PATINA_SDK_REPORT`, `PATINA_DEPTH_REPORT`).
pub(crate) struct GenerationRun {
    pub(super) facts: GenerationFacts,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

impl GenerationRun {
    pub(crate) fn timed_out(&self) -> bool {
        self.facts.facts.timed_out
    }

    pub(crate) fn streams(&self) -> (&str, &str) {
        (&self.stdout, &self.stderr)
    }

    /// What the run reported through the verdict ABI. Read off the child's own
    /// envelope by [`recognize_verdicts`], so a reducer judging a candidate asks
    /// the same question of it the classifier asked of the seed generation.
    pub(crate) fn verdicts(&self) -> &[VerdictFacts] {
        &self.facts.facts.verdicts
    }
}

/// Reduce the child run's `patina.result/v1` envelope to the classifier's
/// structured input. Every field is read from the envelope by name — nothing here
/// parses a diagnostic line back.
pub(super) fn facts_from_envelope(envelope: &serde_json::Value) -> RunFacts {
    let string = |value: Option<&serde_json::Value>| {
        value
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let verdicts = recognize_verdicts(envelope);
    let findings = envelope
        .get("runtime_findings")
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| FindingFacts {
                    source: string(row.get("source")),
                    kind: string(row.get("kind")),
                    known_limit: row
                        .get("known_limit")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();
    let vacuous_planes = envelope
        .get("fault_reports")
        .and_then(serde_json::Value::as_object)
        .map(|planes| {
            planes
                .iter()
                .filter(|(_, plane)| {
                    plane
                        .get("vacuous")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                })
                .map(|(name, _)| name.clone())
                .collect()
        })
        .unwrap_or_default();
    RunFacts {
        exit_code: envelope
            .get("exit_code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_default() as i32,
        signal: envelope
            .get("guest_exit")
            .and_then(|exit| exit.get("signal"))
            .and_then(serde_json::Value::as_i64)
            .map(|signal| signal as i32),
        timed_out: false,
        envelope: true,
        refusal: envelope
            .get("refusal")
            .and_then(|refusal| refusal.get("class"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        refusal_guest_exit_code: envelope
            .get("refusal")
            .and_then(|refusal| refusal.get("guest_exit_code"))
            .and_then(serde_json::Value::as_i64)
            .map(|code| code as i32),
        verdicts,
        vacuous_planes,
        findings,
    }
}

/// A child's own `patina.result/v1` run envelope, if it produced one. The
/// envelope is a single JSON line on stdout; anything else the child wrote there
/// is guest output the envelope itself carries, so the scan takes the last
/// well-formed envelope line and is never confused by a guest that prints JSON.
///
/// The verb is `run` for a `replay` child too: the envelope describes the run
/// that happened, not the command that asked for it.
///
/// Only a run envelope counts. Under `--format json` a CLI-side failure emits an
/// envelope of its own (`verb: "cli"`, `result: "error"`) — a build failure, a
/// pre-run gate refusal, a supervisor error. That is patina declining to run the
/// child at all, not a result for it: for a campaign generation it classifies
/// INFRA through the no-envelope rule, and for a `minimize` candidate it means
/// the candidate reported nothing and is rejected.
pub(crate) fn run_envelope(stdout: &str) -> Option<serde_json::Value> {
    stdout.lines().rev().find_map(|line| {
        let line = line.trim();
        if !line.starts_with('{') {
            return None;
        }
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        let field = |key: &str| value.get(key).and_then(serde_json::Value::as_str);
        (field("schema") == Some(crate::output::ENVELOPE_SCHEMA) && field("verb") == Some("run"))
            .then_some(value)
    })
}

/// Run one generation as a child `cargo patina run --record --format json`
/// process, capturing its result envelope. The virtual-time watchdog and the
/// child's own step/fuel budgets bound the *deterministic* run, but a guest can
/// still wedge in a way none of those observe (an uninterposed atomics-only busy
/// loop). `timeout_secs` is a wall-clock backstop: a generation that overruns it
/// is killed and reported (as INFRA), so a single hung generation can never wedge
/// the whole campaign.
///
/// `--format json` is what makes the classifier structural: the child reports its
/// verdicts, per-plane fault accounting, runtime findings, refusal, and exit
/// status as named envelope fields, and the campaign never has to read them back
/// out of human diagnostics. A child that dies before it can emit an envelope is
/// itself a fact (`RunFacts::envelope`), and classifies INFRA.
pub(super) struct GenerationFiles<'a> {
    pub(super) trace_path: &'a Path,
    pub(super) coverage_out: Option<&'a Path>,
}

pub(super) fn run_generation(
    self_exe: &Path,
    artifact: &Path,
    seed: u64,
    flags: &[String],
    files: GenerationFiles<'_>,
    guest_args: &[String],
    timeout_secs: u64,
) -> Result<GenerationRun, CliError> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut command = Command::new(self_exe);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
        .arg("run")
        .arg("--no-config")
        // The structured outcome channel: the child reports its result as a
        // `patina.result/v1` envelope rather than as diagnostics the campaign
        // would have to grep. This is the classifier's ONLY input.
        .arg("--format")
        .arg("json")
        .arg(artifact)
        .arg("--seed")
        .arg(seed.to_string())
        .arg("--record")
        .arg(files.trace_path);
    for flag in flags {
        command.arg(flag);
    }
    if let Some(path) = files.coverage_out {
        command.arg("--coverage-out").arg(path);
    }
    if !guest_args.is_empty() {
        command.arg("--");
        for arg in guest_args {
            command.arg(arg);
        }
    }
    // Keep the child's diagnostics deterministic and machine-parseable. For a
    // campaign these lines are not cosmetic: they are the measurement channel and
    // the only input the vacuity classifiers have, so an inherited
    // `PATINA_*_REPORT=0` must never reach a generation and turn a blind run into
    // a clean one. Pin every report on, from the same table the families forward,
    // so a report added to the runtime is protected the day it exists.
    crate::config::scrub_child_config_env(&mut command, "run");
    for report in patina_dst_runtime::Report::ALL {
        command.env(report.env(), "1");
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| CliError(format!("failed to spawn generation run: {e}")))?;

    // Drain both pipes CONCURRENTLY with the timeout poll below. The poll loop
    // does not read the pipes; a generation whose envelope (stdout) or report
    // lines (stderr) exceed the pipe buffer — a guest with hundreds of SDK
    // sites prints a PATINA_SDK_REPORT line well past 64 KiB — would block on
    // write, never exit, and be misclassified as INFRA/timeout. Reader threads
    // keep the pipes flowing; their bytes are what the classifier reads.
    fn drain(
        stream: Option<impl std::io::Read + Send + 'static>,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut stream) = stream {
                let _ = std::io::Read::read_to_end(&mut stream, &mut bytes);
            }
            bytes
        })
    }
    let stdout_reader = drain(child.stdout.take());
    let stderr_reader = drain(child.stderr.take());

    let mut timed_out = false;
    if timeout_secs > 0 {
        // Poll the child to completion, killing it if it overruns the wall-clock
        // budget. The reader threads above keep both pipes drained, so a child
        // can never be wedged on a full pipe while this loop waits for it; a
        // genuinely wedged guest is killed at the deadline. `timeout_secs == 0`
        // disables the backstop (poll-free wait).
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            match child
                .try_wait()
                .map_err(|e| CliError(format!("failed to poll generation run: {e}")))?
            {
                Some(_) => break,
                None => {
                    if Instant::now() >= deadline {
                        kill_generation_process_tree(&mut child);
                        timed_out = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }

    let status = child
        .wait()
        .map_err(|e| CliError(format!("failed to collect generation run output: {e}")))?;
    if timed_out {
        // Reaping the child reaped only the process-group LEADER. The guest it
        // supervises was signalled in the same `kill` but dies on its own
        // schedule, and until it has, it still holds the trace scratch file's
        // lock through the descriptor it inherited: the sweep that follows would
        // spare that file as a live recorder's. The generation is over when its
        // last process is.
        #[cfg(unix)]
        await_process_group_exit(child.id(), KILLED_GROUP_EXIT_BOUND);
    }
    let stdout_bytes = stdout_reader.join().unwrap_or_default();
    let stderr_bytes = stderr_reader.join().unwrap_or_default();
    let exit = status.code().unwrap_or(-1);
    // The signal the CHILD itself died on. `code()` is `None` for a signalled
    // child, and `-1` says nothing about why — so a `cargo patina run` the OOM
    // killer took out (it dies alongside its guest under memory pressure) would
    // otherwise be indistinguishable from any other envelope-less failure.
    #[cfg(unix)]
    let child_signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    };
    #[cfg(not(unix))]
    let child_signal: Option<i32> = None;
    let child_stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let child_stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();

    // The child's own captured guest output travels inside the envelope; without
    // one (a build failure, a pre-run refusal, a timeout kill) the child's raw
    // streams are all there is.
    let envelope = run_envelope(&child_stdout);
    let mut facts = match &envelope {
        Some(envelope) => facts_from_envelope(envelope),
        None => RunFacts {
            exit_code: exit,
            ..RunFacts::default()
        },
    };
    // The process exit status is the campaign's own observation and stays
    // authoritative: a child killed after it printed its envelope did not exit
    // with the code that envelope reported.
    facts.exit_code = exit;
    // The envelope's `guest_exit.signal` is the authority when there is one (it
    // is the GUEST's death, one process further in); the campaign's own
    // observation of the child fills in when there is not.
    facts.signal = facts.signal.or(child_signal);
    facts.timed_out = timed_out;
    let envelope_stream = |key: &str| {
        envelope
            .as_ref()
            .and_then(|envelope| envelope.get(key))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    let result_line = envelope_stream("result_line");
    let stdout = envelope_stream("stdout").unwrap_or(child_stdout);
    let mut stderr = envelope_stream("stderr").unwrap_or(child_stderr.clone());
    if envelope.is_some() {
        // A supervisor diagnostic (a trace-finalization note, a build line) rides
        // the child's own stderr rather than the guest's; keep both, so nothing a
        // declared pattern might match is dropped.
        stderr.push_str(&child_stderr);
    }
    if timed_out {
        // Synthetic marker so the killed generation carries a stable signature.
        stderr.push_str(&format!(
            "\npatina: campaign generation exceeded timeout_secs={timeout_secs}\n"
        ));
    }
    Ok(GenerationRun {
        facts: GenerationFacts {
            facts,
            output: format!("{stdout}\n{stderr}"),
            result_line,
        },
        stdout,
        stderr,
    })
}

fn kill_generation_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pgid = -(child.id() as i32);
        // SAFETY: `kill` is called with a process-group id created for this
        // generation's child `cargo patina run`, so the supervisor and its guest
        // are killed together on timeout rather than orphaning a spinning guest.
        let rc = unsafe { kill(pgid, SIGKILL) };
        if rc == 0 {
            return;
        }
    }
    let _ = child.kill();
}

/// How long a SIGKILLed generation's process group may take to vanish before
/// the campaign stops waiting for it. A killed process normally exits within
/// milliseconds even on a loaded host; one that outlasts this is stuck in the
/// kernel (uninterruptible I/O) or is an orphaned zombie nobody reaps.
#[cfg(unix)]
const KILLED_GROUP_EXIT_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Wait until no process of the SIGKILLed generation process group `pgid`
/// remains, and return whether it vanished within `bound`. The caller has
/// already reaped the group's leader; the other members (the guest the leader
/// supervised) died of the same signal but are reparented, and reaped,
/// elsewhere. Their exit is what releases the trace scratch lock they
/// inherited, so only after this returns does the scratch sweep see the file as
/// a dead writer's.
///
/// A member this process is itself the reaper of (the campaign runs as pid 1,
/// or as a child subreaper) is reaped here, since nobody else will. A group
/// that outlasts `bound` is reported and left: the campaign cannot do more than
/// SIGKILL, and a scratch file that then survives the sweep is the loud trace
/// of it.
#[cfg(unix)]
fn await_process_group_exit(pgid: u32, bound: std::time::Duration) -> bool {
    use std::time::{Duration, Instant};

    const ESRCH: i32 = 3;
    const WNOHANG: i32 = 1;
    unsafe extern "C" {
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    }

    let Ok(pgid) = i32::try_from(pgid) else {
        return true;
    };
    let deadline = Instant::now() + bound;
    loop {
        let mut status = 0;
        // SAFETY: `waitpid` writes only through the valid `status` pointer; with
        // a negative pid it reaps only members of this generation's group.
        while unsafe { waitpid(-pgid, &mut status, WNOHANG) } > 0 {}
        // SAFETY: signal 0 delivers nothing; it only probes for group members.
        if unsafe { kill(-pgid, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(ESRCH)
        {
            return true;
        }
        if Instant::now() >= deadline {
            eprintln!(
                "patina: warning: process group {pgid} of a timed-out campaign generation \
                 still has members {}s after SIGKILL; its trace scratch file may be left \
                 in the out-dir",
                bound.as_secs()
            );
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A timed-out generation's trace scratch file is swept only once the last
    /// process holding it is gone. The backstop SIGKILLs the generation's whole
    /// process group but reaps only its leader (the child `cargo patina run`);
    /// the guest that leader supervised holds the scratch lock through an
    /// inherited descriptor and dies on its own schedule. Sweeping as soon as
    /// the leader was reaped spared the file as a live recorder's, and on a
    /// loaded host a timed-out campaign left it in `<out-dir>/traces/`.
    ///
    /// Here the straggler is forced rather than hoped for: the leader exits by
    /// itself and a member holding the lock lives on, so the sweep deterministically
    /// sees the state the old code swept in. Class-level pairing: the
    /// `campaign_timeout_does_not_save_incomplete_trace` end-to-end test asserts
    /// the out-dir invariant itself (no scratch of any name survives a timed-out
    /// generation), and `await_process_group_exit` is the one choke point every
    /// timeout kill passes through before `run_generation` returns.
    #[cfg(unix)]
    #[test]
    fn a_killed_generation_is_swept_only_after_its_last_process_is_gone() {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        use std::time::Duration;

        unsafe extern "C" {
            fn fcntl(fd: i32, cmd: i32, ...) -> i32;
        }
        const F_SETFD: i32 = 2;

        let dir = tempfile::tempdir().expect("tempdir");
        let trace = dir.path().join("generation-0.patina");
        let (scratch, file) = crate::create_scratch(&trace).expect("scratch");
        let fd = file.as_raw_fd();
        // The leader exits at once; the member it backgrounds inherits the
        // locked scratch descriptor, as the guest inherits `PATINA_TRACE_FD`.
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("sleep 60 & exit 0").process_group(0);
        // SAFETY: `fcntl` is async-signal-safe, and clearing `FD_CLOEXEC` here
        // touches only the forked child's descriptor table, never this test
        // process's (which other tests spawn from concurrently).
        unsafe {
            command.pre_exec(move || {
                if fcntl(fd, F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut leader = command.spawn().expect("spawn the generation group");
        drop(file);
        assert!(leader.wait().expect("reap the leader").success());
        let pgid = leader.id();

        // The state the old code swept in: the leader is reaped, a member is
        // not, and the sweep rightly spares a held lock.
        crate::remove_dead_scratch(&trace);
        assert!(
            scratch.exists(),
            "the straggler must still hold the scratch lock, or this test proves nothing"
        );

        // What the timeout backstop does: SIGKILL the group, then await it.
        // SAFETY: signalling the process group this test created.
        assert_eq!(unsafe { kill(-(pgid as i32), SIGKILL) }, 0);
        assert!(
            await_process_group_exit(pgid, Duration::from_secs(30)),
            "a SIGKILLed group must vanish"
        );
        // SAFETY: signal 0 only probes for members.
        assert_ne!(
            unsafe { kill(-(pgid as i32), 0) },
            0,
            "no member of the group may remain once the wait returns"
        );
        crate::remove_dead_scratch(&trace);
        assert!(
            !scratch.exists(),
            "once the last holder is gone the sweep must remove the scratch file"
        );
    }
}
