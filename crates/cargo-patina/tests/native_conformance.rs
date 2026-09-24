//! Syscall conformance (docs/arcs/syscall-conformance.md): every scenario of
//! `crates/patina-conformance`, natively — the host kernel is the oracle — and
//! under `cargo patina`, in the same test, through every vehicle it has.
//!
//! Per vehicle: the native run passes (every check holds) and agrees with the
//! scenario's first vehicle; the patina run equals it or fails exactly as the
//! scenario's gaps declare. A patina run that completes is also recorded and
//! replayed (identical streams; the scenario's trace facts) and run directly
//! under strace (no host syscall escapes; the process ends as it did
//! natively). A host that cannot be the oracle (a kernel lacking a covered
//! row or older than the scenario's kernel floor, or a run-directory
//! filesystem, per-user limit or privilege level lacking what the scenario
//! needs) prints `NOT RUN` with the detected reason; a detection that fails
//! unexpectedly is a failure. A host kernel implementing rows past the virtual
//! ABI level is still an oracle: those rows answer their declared ENOSYS in
//! the native run (only their native observation is not run);
//! `PATINA_REQUIRE_HOST_ORACLE=1`, `PATINA_REQUIRE_SUD=1` and
//! `PATINA_REQUIRE_STRACE=1` (set in CI) make the host, SUD and strace cases
//! failures instead. Every run's streams and logs are kept under the target
//! dir's `conformance/<scenario>/<vehicle>/`.
#![cfg(target_os = "linux")]
mod common;

use patina_dst_conformance::catalog::{self, Scenario};
use patina_dst_conformance::compare::{self, Failure, Observation, Termination};
use patina_dst_conformance::host::{self, Cause, NotRun};
use patina_dst_conformance::leak;
use patina_dst_conformance::observe::parse_stream;
use patina_dst_conformance::owned;
use patina_dst_conformance::vehicle::Vehicle;
use serde_json::Value;
use std::io::Write;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

/// How long one run may take before its process group is killed.
const RUN_DEADLINE: Duration = Duration::from_secs(60);
/// The seed of every `cargo patina` run.
const PATINA_SEED: &str = "1";
/// The seed of the shim-linked binary run directly (no `cargo patina`).
const DIRECT_SEED: &str = "9";
const FINGERPRINT: &str = "patina-conformance";
/// The virtual kernel's descriptor limit and initial umask: the native run
/// starts from the same process state (and with only the three standard
/// descriptors), so allocation order, `EMFILE`, the `F_DUPFD`/`dup2` bounds and
/// the first `umask(2)` answer fall the same way.
const FD_LIMIT: libc::rlim_t = 1024;
const UMASK: libc::mode_t = 0o022;

/// The probe binary built plainly (the native oracle) and shim-linked, both
/// under this test build's target base.
struct Probes {
    native: PathBuf,
    patina: PathBuf,
}

fn probes() -> &'static Probes {
    static PROBES: OnceLock<Probes> = OnceLock::new();
    PROBES.get_or_init(|| {
        let native_target = common::guest_target_dir("conformance-native");
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args([
                "build",
                "--quiet",
                "--locked",
                "--release",
                "--manifest-path",
            ])
            .arg(common::workspace_manifest())
            .args(["-p", "patina-dst-conformance", "--bin", "conformance-probe"])
            .arg("--target-dir")
            .arg(&native_target)
            .status()
            .expect("cargo build runs");
        assert!(
            status.success(),
            "building the native conformance probe failed"
        );
        let patina_target = common::guest_target_dir("conformance");
        let patina = patina_target.join("conformance-probe");
        let package = common::native_workspace().join("crates/patina-conformance");
        common::invoke_in_with_env(
            common::native_workspace(),
            &[
                "build",
                package.to_str().unwrap(),
                "--bin",
                "conformance-probe",
                "--release",
                "--output",
                patina.to_str().unwrap(),
            ],
            &[("CARGO_TARGET_DIR", patina_target.to_str().unwrap())],
        );
        Probes {
            native: native_target.join("release/conformance-probe"),
            patina,
        }
    })
}

fn logs_root() -> PathBuf {
    common::profile_dir()
        .parent()
        .expect("profile has a target base")
        .join("conformance")
}

/// Run `command` with stdin at EOF under the run deadline.
fn run(command: &mut Command) -> Result<Output, String> {
    command.stdin(Stdio::null());
    common::output_with_deadline(command, RUN_DEADLINE)
        .ok_or_else(|| format!("exceeded {RUN_DEADLINE:?}: {command:?}"))
}

fn termination(status: ExitStatus) -> Termination {
    match (status.code(), status.signal()) {
        (Some(code), _) => Termination::Exited(code),
        (None, Some(signal)) => Termination::Signaled {
            signal,
            core: Some(status.core_dumped()),
        },
        (None, None) => Termination::Unreported,
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A process run that wrote the stream itself (native, or shim-linked directly).
fn direct_observation(output: &Output) -> Result<Observation, String> {
    Ok(Observation {
        events: parse_stream(&text(&output.stdout))?,
        termination: termination(output.status),
        stderr: text(&output.stderr),
    })
}

/// A `cargo patina … --format json` run: the guest's streams and exit are in
/// the `patina.result/v1` envelope; a refusal's message joins the stderr.
fn envelope_observation(output: &Output) -> Result<Observation, String> {
    let envelope: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "not a patina.result/v1 envelope ({error}); cargo-patina {}: {}",
            output.status,
            text(&output.stderr)
        )
    })?;
    let guest_exit = &envelope["guest_exit"];
    let termination = match (guest_exit["signal"].as_i64(), guest_exit["code"].as_i64()) {
        (Some(signal), _) => Termination::Signaled {
            signal: signal as i32,
            core: guest_exit["core"].as_bool(),
        },
        (None, Some(code)) => Termination::Exited(code as i32),
        (None, None) => Termination::Unreported,
    };
    Ok(Observation {
        events: parse_stream(envelope["stdout"].as_str().unwrap_or(""))?,
        termination,
        stderr: format!(
            "{}{}{}",
            text(&output.stderr),
            envelope["stderr"].as_str().unwrap_or(""),
            envelope["refusal"]["message"].as_str().unwrap_or("")
        ),
    })
}

/// The first descriptor past the standard three.
const FIRST_UNSTANDARD_FD: libc::c_uint = 3;

/// Pin the native process state the virtual kernel starts from: every
/// descriptor the test process inherited past the standard three closes at
/// exec, and the descriptor limit and umask are the virtual kernel's.
/// `CLOSE_RANGE_CLOEXEC` needs Linux 5.11; an older host fails every native
/// run here instead of reporting it not run.
fn pin_process_state() -> std::io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: async-signal-safe calls on this (forked) process's own state.
    unsafe {
        if libc::close_range(
            FIRST_UNSTANDARD_FD,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC as libc::c_int,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        limit.rlim_cur = FD_LIMIT;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::umask(UMASK);
    }
    Ok(())
}

/// Report a run that cannot happen on this host. Written past the test
/// harness's capture (`eprintln!` is captured), so it shows on a passing run
/// too.
#[allow(clippy::explicit_write)]
fn not_run(what: &str, reason: &NotRun) {
    writeln!(std::io::stderr(), "NOT RUN {what}: {reason}").unwrap();
}

fn required(variable: &str) -> bool {
    std::env::var(variable).as_deref() == Ok("1")
}

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
struct Leg<'a> {
    scenario: &'a Scenario,
    vehicle: Vehicle,
    /// The same path for every run of the scenario, so recorded paths compare
    /// equal: natively it is emptied before each vehicle's run; under patina
    /// it exists only in the virtual filesystem.
    dir: &'a Path,
    logs: PathBuf,
    /// The host implements rows the scenario asserts absent: the native run
    /// answers them with the declared ENOSYS (`--declared-absent`).
    declared_absent: bool,
}

impl Leg<'_> {
    fn name(&self) -> String {
        format!("{}[{}]", self.scenario.name, self.vehicle.name())
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
        // SAFETY: the hook only calls async-signal-safe libc functions.
        unsafe { command.pre_exec(pin_process_state) };
        let output = run(&mut command);
        // IPC objects outlive a run killed outright (the deadline); the next
        // leg recreates this directory, likely on the same inode and keys.
        owned::sweep(self.dir);
        let output = output?;
        self.keep("native", &output);
        direct_observation(&output)
    }

    fn cargo_patina(&self, run_name: &str, arguments: &[&str]) -> Result<Output, String> {
        let output = run(Command::new(env!("CARGO_BIN_EXE_cargo-patina"))
            .current_dir(common::native_workspace())
            .args(arguments))?;
        self.keep(run_name, &output);
        Ok(output)
    }

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
        let output = self.cargo_patina(
            if record.is_some() { "record" } else { "patina" },
            &arguments,
        )?;
        envelope_observation(&output)
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
        envelope_observation(&output)
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
        direct_observation(&output)
    }

    /// Every check of this leg; `reference` is the scenario's first native
    /// observation, which every other vehicle's must agree with.
    fn check(&self, reference: &mut Option<(Vehicle, Observation)>) -> Result<(), Vec<String>> {
        let native = self
            .native()
            .map_err(|error| vec![format!("native run: {error}")])?;
        compare::native_verdict(&native).map_err(|error| {
            vec![format!(
                "the native run is no oracle: {error}\n{}",
                tail(&native.stderr)
            )]
        })?;
        match reference {
            Some((vehicle, first)) => {
                compare::vehicles_agree(first, &native).map_err(|failures| {
                    prefixed(
                        &format!("natively, differs from {}: ", vehicle.name()),
                        failures,
                    )
                })?
            }
            None => *reference = Some((self.vehicle, native.clone())),
        }

        #[cfg(target_arch = "x86_64")]
        if self.vehicle == Vehicle::Raw {
            if let Err(reason) = host::syscall_user_dispatch() {
                if required("PATINA_REQUIRE_SUD") {
                    return Err(vec![format!("PATINA_REQUIRE_SUD=1: {reason}")]);
                }
                not_run(&format!("{} under patina", self.name()), &reason);
                return Ok(());
            }
        }

        let gaps: Vec<&catalog::Gap> = self.scenario.gaps_for(self.vehicle).collect();
        let reasons: Vec<String> = gaps.iter().map(|gap| gap.reason()).collect();
        let expected: Vec<compare::Expected<'_>> = gaps
            .iter()
            .zip(&reasons)
            .map(|(gap, reason)| gap.expected(reason))
            .collect();
        let patina = self
            .patina(None)
            .map_err(|error| vec![format!("patina run: {error}")])?;
        compare::judge(&native, &patina, &expected)
            .map_err(|failures| with_stderr(prefixed("patina: ", failures), &patina))?;
        if gaps
            .iter()
            .any(|gap| matches!(gap.failure, Failure::Stops { .. }))
        {
            // A stopped run leaves no complete trace, and the direct run would
            // be the same refusal outside the supervisor.
            return Ok(());
        }

        let trace = self.logs.join("run.patina");
        let recorded = self
            .patina(Some(&trace))
            .map_err(|error| vec![format!("record: {error}")])?;
        compare::judge(&native, &recorded, &expected)
            .map_err(|failures| with_stderr(prefixed("record: ", failures), &recorded))?;
        let replayed = self
            .replay(&trace)
            .map_err(|error| vec![format!("replay: {error}")])?;
        if replayed.events != recorded.events || replayed.termination != recorded.termination {
            return Err(vec![format!(
                "replay: the replayed stream differs from the recorded one ({} vs {} events; {} vs {})",
                replayed.events.len(),
                recorded.events.len(),
                replayed.termination,
                recorded.termination
            )]);
        }
        if let Some(facts) = &self.scenario.trace {
            let ops = self.trace_ops(&trace).map_err(|error| vec![error])?;
            facts
                .check(&ops)
                .map_err(|unmet| prefixed("recorded trace: ", unmet))?;
        }

        self.check_leak(&native)
    }

    fn check_leak(&self, native: &Observation) -> Result<(), Vec<String>> {
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
        if ending(traced.termination) != ending(native.termination) {
            return Err(vec![format!(
                "under strace the probe ended {}; natively {}\n{}",
                traced.termination,
                native.termination,
                tail(&traced.stderr)
            )]);
        }
        // A signal death is checked once more with nothing in between: the
        // shim-linked binary's own wait status, signal and core flag.
        if matches!(native.termination, Termination::Signaled { .. }) {
            let direct = self
                .direct(None)
                .map_err(|error| vec![format!("direct run: {error}")])?;
            if direct.termination != native.termination {
                return Err(vec![format!(
                    "run directly the probe ended {}; natively {}",
                    direct.termination, native.termination
                )]);
            }
        }
        Ok(())
    }
}

fn prefixed(prefix: &str, lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| format!("{prefix}{line}"))
        .collect()
}

fn with_stderr(mut failures: Vec<String>, observation: &Observation) -> Vec<String> {
    failures.push(tail(&observation.stderr));
    failures
}

/// The last lines of a run's stderr, for a failure message.
fn tail(stderr: &str) -> String {
    const LINES: usize = 12;
    let lines: Vec<&str> = stderr.lines().collect();
    let start = lines.len().saturating_sub(LINES);
    format!("stderr (tail):\n    {}", lines[start..].join("\n    "))
}

/// Run `name` natively and under patina through every vehicle it has.
fn conform(name: &str) {
    let scenario = catalog::scenario(name).unwrap_or_else(|| panic!("no scenario {name:?}"));
    if let Some(reason) = host::scenario_unmet(scenario) {
        assert!(
            !required("PATINA_REQUIRE_HOST_ORACLE"),
            "PATINA_REQUIRE_HOST_ORACLE=1 but this host kernel is no oracle for {name}: {reason}"
        );
        not_run(name, &reason);
        return;
    }
    let logs = logs_root().join(name.replace('/', "-"));
    let _ = std::fs::remove_dir_all(&logs);
    let owned = tempfile::Builder::new()
        .prefix("patina-conformance-")
        .tempdir()
        .expect("create the scenario's directory");
    if let Some((need, reason)) = host::needs_unmet(scenario, owned.path()) {
        assert!(
            reason.cause != Cause::Unexpected,
            "detecting what {name} needs failed: {reason}"
        );
        // A machine fact found absent (no protection keys on this CPU) is no
        // misconfigured host: not run even where an oracle is required.
        assert!(
            (need.hardware() && reason.cause == Cause::Absent)
                || !required("PATINA_REQUIRE_HOST_ORACLE"),
            "PATINA_REQUIRE_HOST_ORACLE=1 but this host is no oracle for {name}: {reason}"
        );
        not_run(name, &reason);
        return;
    }
    // A host kernel newer than the virtual ABI level is no broken oracle: the
    // rows it implements past that level answer the declared ENOSYS natively,
    // and only their native observation is not run.
    let declared_absent = host::declared_absent(scenario);
    if let Some(reason) = &declared_absent {
        not_run(&format!("{name}: native observation"), reason);
    }
    let dir = owned.path().join("run");
    let mut reference = None;
    let mut failures = Vec::new();
    for &vehicle in scenario.vehicles {
        let leg = Leg {
            scenario,
            vehicle,
            dir: &dir,
            logs: logs.join(vehicle.name()),
            declared_absent: declared_absent.is_some(),
        };
        std::fs::create_dir_all(&leg.logs).unwrap();
        if let Err(leg_failures) = leg.check(&mut reference) {
            failures.extend(prefixed(&format!("{}: ", leg.name()), leg_failures));
        }
    }
    assert!(
        failures.is_empty(),
        "{name}: {} failure(s)\n{}\nlogs: {}",
        failures.len(),
        failures.join("\n"),
        logs.display()
    );
}

#[test]
fn every_scenario_has_one_test() {
    let source = include_str!("native_conformance.rs");
    for scenario in catalog::SCENARIOS {
        let call = format!("conform(\"{}\");", scenario.name);
        assert_eq!(
            source.matches(&call).count(),
            1,
            "{} needs exactly one test calling {call}",
            scenario.name
        );
    }
}

/// A native IPC run killed outright unwinds none of its guards. Each IPC
/// scenario is SIGKILLed on entering its second creating call — strace injects
/// the signal, so the point is exact: its first keyed object (or its queue)
/// exists and nothing private does yet. The object is really left behind, the
/// sweep every native run gets removes it and nothing else is left under the
/// run's names, and the next run on the recreated directory is an oracle
/// again.
#[test]
fn a_killed_native_ipc_run_is_swept() {
    if let Err(reason) = strace() {
        assert!(
            !required("PATINA_REQUIRE_STRACE"),
            "PATINA_REQUIRE_STRACE=1: {reason}"
        );
        not_run("the killed IPC runs", reason);
        return;
    }
    let cases = [
        ("ipc/sysv_shm", "shmget"),
        ("ipc/sysv_sem", "semget"),
        ("ipc/sysv_msg", "msgget"),
        ("ipc/mqueue", "mq_open"),
    ];
    for (name, creator) in cases {
        let scenario = catalog::scenario(name).expect("an IPC scenario");
        let owned = tempfile::Builder::new()
            .prefix("patina-conformance-")
            .tempdir()
            .unwrap();
        if let Some((_, reason)) = host::needs_unmet(scenario, owned.path()) {
            assert!(
                !required("PATINA_REQUIRE_HOST_ORACLE"),
                "PATINA_REQUIRE_HOST_ORACLE=1 but this host is no oracle for {name}: {reason}"
            );
            not_run(&format!("{name} killed"), &reason);
            continue;
        }
        let dir = owned.path().join("run");
        let mut command = Command::new("strace");
        command
            .args(["-f", "-o", "/dev/null", "-e"])
            .arg(format!("inject={creator}:signal=KILL:when=2"))
            .arg(&probes().native)
            .args([name, "--vehicle", "syscall", "--dir"])
            .arg(&dir)
            .arg("--strict");
        // SAFETY: the hook only calls async-signal-safe libc functions.
        unsafe { command.pre_exec(pin_process_state) };
        let output = run(&mut command).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(
            output.status.signal() == Some(libc::SIGKILL)
                || output.status.code() == Some(128 + libc::SIGKILL),
            "{name}: not killed at its second {creator} ({}): {}",
            output.status,
            text(&output.stderr)
        );
        let swept = owned::sweep(&dir);
        assert_eq!(
            swept.len(),
            1,
            "{name}: the killed run left exactly its one named object: {swept:?}"
        );
        assert_eq!(
            owned::sweep(&dir),
            Vec::<String>::new(),
            "{name}: swept twice"
        );
        let logs = logs_root().join(format!("{}-killed", name.replace('/', "-")));
        std::fs::create_dir_all(&logs).unwrap();
        let leg = Leg {
            scenario,
            vehicle: Vehicle::Syscall,
            dir: &dir,
            logs,
            declared_absent: false,
        };
        let rerun = leg
            .native()
            .unwrap_or_else(|error| panic!("{name}: rerun: {error}"));
        compare::native_verdict(&rerun)
            .unwrap_or_else(|error| panic!("{name}: the run after the kill is no oracle: {error}"));
        assert_eq!(
            owned::sweep(&dir),
            Vec::<String>::new(),
            "{name}: a completed run leaves nothing to sweep"
        );
    }
}

#[test]
fn strace_leak_filter_flags_a_planted_escape() {
    if let Err(reason) = strace() {
        assert!(
            !required("PATINA_REQUIRE_STRACE"),
            "PATINA_REQUIRE_STRACE=1: {reason}"
        );
        not_run("the planted strace escape", reason);
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("strace.log");
    let output = run(Command::new("strace")
        .args(["-f", "-s", "4096", "-e", leak::STRACE_EVENTS, "-o"])
        .arg(&log)
        .arg(&probes().native)
        .args(["planted/escape", "--vehicle", "syscall", "--dir"])
        .arg(dir.path()))
    .unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    let escaped = leak::escapes(&std::fs::read_to_string(&log).unwrap());
    assert!(
        escaped
            .iter()
            .any(|line| line.starts_with("openat(") && line.contains("\"/etc/hostname\"")),
        "the planted escape was not flagged: {escaped:?}"
    );
}

#[test]
fn abi_newer_than_virtual() {
    conform("abi/newer-than-virtual");
}

#[test]
fn entropy_getrandom() {
    conform("entropy/getrandom");
}

#[test]
fn fd_pipes() {
    conform("fd/pipes");
}

#[test]
fn fd_table() {
    conform("fd/table");
}

#[test]
fn fs_cache() {
    conform("fs/cache");
}

#[test]
fn fs_chmod() {
    conform("fs/chmod");
}

#[test]
fn fs_copy() {
    conform("fs/copy");
}

#[test]
fn fs_dirs() {
    conform("fs/dirs");
}

#[test]
fn fs_getdents() {
    conform("fs/getdents");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn fs_getdents_legacy() {
    conform("fs/getdents_legacy");
}

#[test]
fn fs_handles() {
    conform("fs/handles");
}

#[test]
fn fs_inotify() {
    conform("fs/inotify");
}

#[test]
fn fs_ioctl() {
    conform("fs/ioctl");
}

#[test]
fn fs_legacy_paths() {
    conform("fs/legacy_paths");
}

#[test]
fn fs_links() {
    conform("fs/links");
}

#[test]
fn fs_metadata() {
    conform("fs/metadata");
}

#[test]
fn fs_newer_than_virtual() {
    conform("fs/newer_than_virtual");
}

#[test]
fn fs_open_rw() {
    conform("fs/open_rw");
}

#[test]
fn fs_openat2() {
    conform("fs/openat2");
}

#[test]
fn fs_owner() {
    conform("fs/owner");
}

#[test]
fn fs_paths() {
    conform("fs/paths");
}

#[test]
fn fs_positional_io() {
    conform("fs/positional_io");
}

#[test]
fn fs_renameat2() {
    conform("fs/renameat2");
}

#[test]
fn fs_size() {
    conform("fs/size");
}

#[test]
fn fs_splice() {
    conform("fs/splice");
}

#[test]
fn fs_statfs() {
    conform("fs/statfs");
}

#[test]
fn fs_statfs_fault() {
    conform("fs/statfs_fault");
}

#[test]
fn fs_sync() {
    conform("fs/sync");
}

#[test]
fn fs_times() {
    conform("fs/times");
}

#[test]
fn fs_vectored_io() {
    conform("fs/vectored_io");
}

#[test]
fn fs_xattr() {
    conform("fs/xattr");
}

#[test]
fn ipc_mqueue() {
    conform("ipc/mqueue");
}

#[test]
fn ipc_sysv_msg() {
    conform("ipc/sysv_msg");
}

#[test]
fn ipc_sysv_sem() {
    conform("ipc/sysv_sem");
}

#[test]
fn ipc_sysv_shm() {
    conform("ipc/sysv_shm");
}

#[test]
fn mem_brk() {
    conform("mem/brk");
}

#[test]
fn mem_membarrier() {
    conform("mem/membarrier");
}

#[test]
fn mem_memfd() {
    conform("mem/memfd");
}

#[test]
fn mem_mincore() {
    conform("mem/mincore");
}

#[test]
fn mem_mlock() {
    conform("mem/mlock");
}

#[test]
fn mem_mmap() {
    conform("mem/mmap");
}

#[test]
fn mem_mmap_file() {
    conform("mem/mmap_file");
}

#[test]
fn mem_mremap() {
    conform("mem/mremap");
}

#[test]
fn mem_mseal() {
    conform("mem/mseal");
}

#[test]
fn mem_msync() {
    conform("mem/msync");
}

#[test]
fn mem_numa() {
    conform("mem/numa");
}

#[test]
fn mem_pkeys() {
    conform("mem/pkeys");
}

#[test]
fn mem_process_madvise() {
    conform("mem/process_madvise");
}

#[test]
fn mem_process_madvise_self() {
    conform("mem/process_madvise_self");
}

#[test]
fn mem_protect() {
    conform("mem/protect");
}

#[test]
fn mem_remap_file_pages() {
    conform("mem/remap_file_pages");
}

#[test]
fn mem_secret() {
    conform("mem/secret");
}

#[test]
fn mem_shadow_stack() {
    conform("mem/shadow_stack");
}

#[test]
fn net_tcp() {
    conform("net/tcp");
}

#[test]
fn net_udp() {
    conform("net/udp");
}

#[test]
fn proc_absent() {
    conform("proc/absent");
}

#[test]
fn proc_ids() {
    conform("proc/ids");
}

#[test]
fn proc_prctl() {
    conform("proc/prctl");
}

#[test]
fn proc_traps() {
    conform("proc/traps");
}

#[test]
fn proc_wait() {
    conform("proc/wait");
}

#[test]
fn readiness_epoll() {
    conform("readiness/epoll");
}

#[test]
fn readiness_ppoll() {
    conform("readiness/ppoll");
}

#[test]
fn signal_altstack() {
    conform("signal/altstack");
}

#[test]
fn signal_basic() {
    conform("signal/basic");
}

#[test]
fn signal_block() {
    conform("signal/block");
}

#[test]
fn signal_core_term() {
    conform("signal/core_term");
}

#[test]
fn signal_default() {
    conform("signal/default");
}

#[test]
fn signal_default_term() {
    conform("signal/default_term");
}

#[test]
fn signal_eintr() {
    conform("signal/eintr");
}

#[test]
fn signal_mask() {
    conform("signal/mask");
}

#[test]
fn signal_nested() {
    conform("signal/nested");
}

#[test]
fn signal_one_wake() {
    conform("signal/one_wake");
}

#[test]
fn signal_per_thread() {
    conform("signal/per_thread");
}

#[test]
fn signal_pipe() {
    conform("signal/pipe");
}

#[test]
fn signal_pipe_term() {
    conform("signal/pipe_term");
}

#[test]
fn signal_queue() {
    conform("signal/queue");
}

#[test]
fn signal_raw_action() {
    conform("signal/raw_action");
}

#[test]
fn signal_resethand_term() {
    conform("signal/resethand_term");
}

#[test]
fn signal_rt_order() {
    conform("signal/rt_order");
}

#[test]
fn signal_unmask() {
    conform("signal/unmask");
}

#[test]
fn signal_wait() {
    conform("signal/wait");
}

#[test]
fn thread_futex() {
    conform("thread/futex");
}

#[test]
fn thread_kill() {
    conform("thread/kill");
}

#[test]
fn thread_lifecycle() {
    conform("thread/lifecycle");
}

#[test]
fn thread_main_exit() {
    conform("thread/main_exit");
}

#[test]
fn thread_masks() {
    conform("thread/masks");
}

#[test]
fn thread_pthread_kill() {
    conform("thread/pthread_kill");
}

#[test]
fn thread_tid_clear() {
    conform("thread/tid_clear");
}

#[test]
fn time_clocks() {
    conform("time/clocks");
}
