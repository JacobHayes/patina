//! Per-vehicle native, patina, replay, trace, and syscall-leak execution checks.

use super::hang::HangWatch;
use super::oracle::{Oracle, judge_native, prefixed, tail, undeclared_death, with_stderr};
use super::process::{
    DIRECT_SEED, FINGERPRINT, PATINA_SEED, RUN_DEADLINE, direct_observation, envelope_observation,
    not_run, pin_process_state, probes, required, run, text,
};
use crate::common;
use patina_dst_conformance::catalog::{self, Need, Scenario};
use patina_dst_conformance::compare::{self, Observation, Origin, Termination};
use patina_dst_conformance::host::{self, Cause, NotRun};
use patina_dst_conformance::observe::parse_stream;
use patina_dst_conformance::vehicle::Vehicle;
use patina_dst_conformance::{leak, owned};
use serde_json::Value;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

/// Whether strace can trace a child here.
fn strace() -> &'static Result<(), NotRun> {
    static STRACE: OnceLock<Result<(), NotRun>> = OnceLock::new();
    STRACE.get_or_init(|| {
        match Command::new("strace")
            .args(["-o", "/dev/null", "true"])
            .output()
        {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(NotRun {
                cause: if text(&output.stderr).contains("Operation not permitted") {
                    Cause::PermissionDenied
                } else {
                    Cause::Sandboxed
                },
                detail: format!(
                    "strace cannot trace a child: {}",
                    text(&output.stderr).trim()
                ),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(NotRun {
                cause: Cause::Absent,
                detail: "strace is not on PATH".into(),
            }),
            Err(error) => panic!("strace discovery: {error}"),
        }
    })
}

/// One scenario through one vehicle: its run directory and its logs.
pub(super) struct Leg<'a> {
    pub(super) scenario: &'a Scenario,
    pub(super) vehicle: Vehicle,
    /// The same path for every run of the scenario, so recorded paths compare
    /// equal: natively it is emptied before each vehicle's run; under patina
    /// it exists only in the virtual filesystem.
    pub(super) dir: &'a Path,
    pub(super) logs: PathBuf,
    /// The host implements rows the scenario asserts absent: the native run
    /// answers them with the declared ENOSYS (`--declared-absent`).
    pub(super) declared_absent: bool,
}

impl Leg<'_> {
    pub(super) fn name(&self) -> String {
        format!("{}[{}]", self.scenario.name, self.vehicle.name())
    }

    /// What this leg's `leg` run of its vehicle observes is.
    fn origin(&self, leg: compare::Leg) -> Origin {
        Origin {
            leg,
            vehicle: self.vehicle,
        }
    }

    fn args(&self) -> Vec<String> {
        vec![
            self.scenario.name.to_string(),
            "--vehicle".into(),
            self.vehicle.name().into(),
            "--dir".into(),
            self.dir.display().to_string(),
        ]
    }

    fn keep(&self, run: &str, output: &Output) {
        std::fs::write(self.logs.join(format!("{run}.stdout")), &output.stdout).unwrap();
        std::fs::write(self.logs.join(format!("{run}.stderr")), &output.stderr).unwrap();
    }

    fn native(&self) -> Result<Observation, String> {
        match std::fs::remove_dir_all(self.dir) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("empty {}: {error}", self.dir.display()));
            }
            _ => {}
        }
        let mut command = Command::new(&probes().native);
        command.args(self.args()).arg("--strict");
        if self.declared_absent {
            command.arg("--declared-absent");
        }
        let needs_keys = self.scenario.needs.contains(&Need::Keys);
        // SAFETY: the hook only calls async-signal-safe libc functions.
        unsafe { command.pre_exec(move || pin_process_state(needs_keys)) };
        let output = run(&mut command);
        // IPC objects outlive a run killed outright (the deadline); the next
        // leg recreates this directory, likely on the same inode and keys.
        owned::sweep(self.dir);
        let output = output?;
        self.keep("native", &output);
        direct_observation(&output, self.origin(compare::Leg::Native))
    }

    fn cargo_patina(&self, run_name: &str, arguments: &[&str]) -> Result<Output, String> {
        let output = run(Command::new(env!("CARGO_BIN_EXE_cargo-patina"))
            .current_dir(common::native_workspace())
            .args(arguments))?;
        self.keep(run_name, &output);
        Ok(output)
    }

    /// The patina run. A vehicle whose gap declares a hang runs under that
    /// gap's short deadline, and a run killed there is an observation (it
    /// recorded no complete envelope, so no event), not a failure.
    fn patina(&self, record: Option<&Path>) -> Result<Observation, String> {
        let binary = probes().patina.display().to_string();
        let trace = record.map(|path| path.display().to_string());
        let mut arguments = vec!["run", &binary, "--seed", PATINA_SEED, "--format", "json"];
        if let Some(trace) = &trace {
            arguments.extend(["--record", trace, "--fingerprint", FINGERPRINT]);
        }
        arguments.push("--");
        let args = self.args();
        arguments.extend(args.iter().map(String::as_str));
        let run_name = if record.is_some() { "record" } else { "patina" };
        let hang = self
            .scenario
            .gaps_for(self.vehicle)
            .find_map(|gap| gap.failure.hang_deadline());
        let Some(within) = hang else {
            let output = self.cargo_patina(run_name, &arguments)?;
            return envelope_observation(&output, self.origin(compare::Leg::Patina));
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-patina"));
        command
            .current_dir(common::native_workspace())
            .args(&arguments)
            .stdin(Stdio::null());
        let mut watch = HangWatch::new(within, &probes().patina)?;
        let outcome = common::output_until(&mut command, RUN_DEADLINE, |supervisor| {
            watch.confirmed(supervisor)
        });
        match outcome {
            common::Deadlined::Finished(output) => {
                self.keep(run_name, &output);
                // The watch's last look, kept beside a leg that completed
                // (never confirmed: it progressed or had not stalled long).
                std::fs::write(self.logs.join(format!("{run_name}.hang")), &watch.last_seen)
                    .unwrap();
                envelope_observation(&output, self.origin(compare::Leg::Patina))
            }
            common::Deadlined::Killed { stdout, stderr } => {
                std::fs::write(self.logs.join(format!("{run_name}.stdout")), &stdout).unwrap();
                std::fs::write(self.logs.join(format!("{run_name}.stderr")), &stderr).unwrap();
                std::fs::write(self.logs.join(format!("{run_name}.hang")), &watch.last_seen)
                    .unwrap();
                let Some(journal) = watch.journal else {
                    return Err(format!(
                        "exceeded {RUN_DEADLINE:?} without a confirmed hang (last look at the guest: {})",
                        watch.last_seen
                    ));
                };
                Ok(Observation {
                    origin: self.origin(compare::Leg::Patina),
                    events: parse_stream(&text(&journal))?,
                    termination: Termination::Hung,
                    stderr: format!("{}\nconfirmed stuck: {}", text(&stderr), watch.last_seen),
                })
            }
        }
    }

    fn replay(&self, trace: &Path) -> Result<Observation, String> {
        let binary = probes().patina.display().to_string();
        let trace = trace.display().to_string();
        let output = self.cargo_patina(
            "replay",
            &[
                "replay",
                &binary,
                &trace,
                "--fingerprint",
                FINGERPRINT,
                "--format",
                "json",
            ],
        )?;
        envelope_observation(&output, self.origin(compare::Leg::Patina))
    }

    fn trace_ops(&self, trace: &Path) -> Result<Vec<Value>, String> {
        let trace = trace.display().to_string();
        let output = self.cargo_patina(
            "trace-events",
            &["trace", "events", &trace, "--format", "json"],
        )?;
        if !output.status.success() {
            return Err(format!(
                "cargo patina trace events failed: {}",
                text(&output.stderr)
            ));
        }
        text(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line).map_err(|error| format!("trace events: {error}"))
            })
            .collect()
    }

    /// The shim-linked binary run directly, seeded, optionally under strace.
    fn direct(&self, strace_log: Option<&Path>) -> Result<Observation, String> {
        let binary = &probes().patina;
        let mut command = match strace_log {
            Some(log) => {
                let mut command = Command::new("strace");
                command
                    .args(["-f", "-s", "4096", "-e", leak::STRACE_EVENTS, "-o"])
                    .arg(log)
                    .arg(binary);
                command
            }
            None => Command::new(binary),
        };
        command
            .args(self.args())
            .env_remove("LD_LIBRARY_PATH")
            .env("PATINA_MODE", "seeded")
            .env("PATINA_SEED", DIRECT_SEED);
        let output = run(&mut command)?;
        self.keep(
            if strace_log.is_some() {
                "strace"
            } else {
                "direct"
            },
            &output,
        );
        direct_observation(&output, self.origin(compare::Leg::Patina))
    }

    /// Every check of this leg; `reference` is the scenario's first native
    /// observation, which every other vehicle's must agree with.
    /// `diverged` collects what the oracle only reports.
    pub(super) fn check(
        &self,
        oracle: &Oracle,
        reference: &mut Option<Observation>,
        diverged: &mut Vec<String>,
    ) -> Result<(), Vec<String>> {
        let native = self
            .native()
            .map_err(|error| vec![format!("native run: {error}")])?;
        let compared = judge_native(oracle, &native, reference, diverged)?;

        #[cfg(target_arch = "x86_64")]
        if self.vehicle == Vehicle::Raw
            && let Err(reason) = host::syscall_user_dispatch()
        {
            if required("PATINA_REQUIRE_SUD") {
                return Err(vec![format!("PATINA_REQUIRE_SUD=1: {reason}")]);
            }
            not_run(&format!("{} under patina", self.name()), &reason);
            return Ok(());
        }

        let gaps: Vec<&catalog::Gap> = self.scenario.gaps_for(self.vehicle).collect();
        let reasons: Vec<String> = gaps.iter().map(|gap| gap.reason()).collect();
        let expected: Vec<compare::Expected<'_>> = gaps
            .iter()
            .zip(&reasons)
            .map(|(gap, reason)| gap.expected(reason))
            .collect();
        // The patina run is the recorded one: recording changes nothing it
        // observes (`recording_changes_no_observation`).
        let trace = self.logs.join("run.patina");
        let recorded = self
            .patina(Some(&trace))
            .map_err(|error| vec![format!("patina run: {error}")])?;
        let judgement = if compared {
            compare::judge(&native, &recorded, &expected)
                .map(|_| ())
                .map_err(|failures| prefixed("patina: ", failures))
        } else {
            Ok(())
        };
        if let Some(death) = undeclared_death(&native, &recorded, &gaps) {
            let mut failures = judgement.err().unwrap_or_default();
            failures.push(death);
            return Err(with_stderr(failures, &recorded));
        }
        oracle.judged(
            judgement.map_err(|failures| with_stderr(failures, &recorded)),
            diverged,
        )?;
        if gaps.iter().any(|gap| gap.failure.ends_early()) {
            // A stopped run leaves no complete trace, and the direct run would
            // be the same refusal outside the supervisor.
            return Ok(());
        }
        let replayed = self
            .replay(&trace)
            .map_err(|error| vec![format!("replay: {error}")])?;
        if replayed.events != recorded.events || replayed.termination != recorded.termination {
            return Err(with_stderr(
                vec![format!(
                    "replay: the replayed stream differs from the recorded one ({} vs {} events; {} vs {})",
                    replayed.events.len(),
                    recorded.events.len(),
                    replayed.termination,
                    recorded.termination
                )],
                &recorded,
            ));
        }
        if let Some(facts) = &self.scenario.trace {
            let ops = self.trace_ops(&trace).map_err(|error| vec![error])?;
            facts
                .check(&ops)
                .map_err(|unmet| prefixed("recorded trace: ", unmet))?;
        }

        self.check_leak(&recorded)
    }

    /// The shim-linked binary run directly under strace ends as the
    /// `recorded` run did (on an authoritative host, as natively too).
    fn check_leak(&self, recorded: &Observation) -> Result<(), Vec<String>> {
        if let Err(reason) = strace() {
            if required("PATINA_REQUIRE_STRACE") {
                return Err(vec![format!("PATINA_REQUIRE_STRACE=1: {reason}")]);
            }
            not_run(&format!("{} under strace", self.name()), reason);
            return Ok(());
        }
        let log = self.logs.join("strace.log");
        let traced = self
            .direct(Some(&log))
            .map_err(|error| vec![format!("strace run: {error}")])?;
        let escaped = leak::escapes(&std::fs::read_to_string(&log).unwrap_or_default());
        if !escaped.is_empty() {
            return Err(prefixed("host syscall escaped under strace: ", escaped));
        }
        if traced.events.is_empty() {
            return Err(vec![format!(
                "the strace run recorded no events\n{}",
                tail(&traced.stderr)
            )]);
        }
        // strace ends the way its tracee did (it re-raises a terminating
        // signal on itself); the core flag is strace's own.
        let ending = |termination: Termination| match termination {
            Termination::Signaled { signal, .. } => Termination::Signaled { signal, core: None },
            other => other,
        };
        if ending(traced.termination) != ending(recorded.termination) {
            return Err(vec![format!(
                "under strace the probe ended {}; recorded {}\n{}",
                traced.termination,
                recorded.termination,
                tail(&traced.stderr)
            )]);
        }
        // A signal death is checked once more with nothing in between: the
        // shim-linked binary's own wait status, signal and core flag.
        if matches!(recorded.termination, Termination::Signaled { .. }) {
            let direct = self
                .direct(None)
                .map_err(|error| vec![format!("direct run: {error}")])?;
            if direct.termination != recorded.termination {
                return Err(vec![format!(
                    "run directly the probe ended {}; recorded {}",
                    direct.termination, recorded.termination
                )]);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "leg/tests.rs"]
mod tests;
