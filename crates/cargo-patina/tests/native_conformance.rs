//! Syscall conformance (docs/arcs/syscall-conformance.md): every scenario of
//! `crates/patina-conformance`, natively — the host kernel is the oracle — and
//! under `cargo patina`, in the same test, through every vehicle it has.
//!
//! Per vehicle: the native run passes (every check holds) and agrees with the
//! scenario's first vehicle; the patina run, recorded, equals it or fails
//! exactly as the scenario's gaps declare (a plain run observes the same:
//! `recording_changes_no_observation`). One that completes is also replayed
//! (identical streams; the scenario's trace facts) and run directly
//! under strace (no host syscall escapes; the process ends as the recorded
//! run did).
//!
//! The scenarios assert the pinned system, Ubuntu 24.04: its GA kernel
//! (Linux 6.8, `VIRTUAL_ABI`) and its glibc (2.39, `host::PINNED_GLIBC`), so
//! only a host with both (`host::pinned`) is authoritative: elsewhere
//! (GitHub's runners run 6.17) whatever sets the host apart from patina — a
//! failed native check, a native-versus-patina difference, a gap that no
//! longer matches — is reported, `DIVERGES (host H, pinned P)` on stderr and
//! a section of `$GITHUB_STEP_SUMMARY` when set, and fails nothing;
//! `PATINA_REQUIRE_PINNED_KERNEL=1` judges any host as the pinned one. Native vehicles that disagree, patina's record/replay,
//! trace and strace checks, and runs that crash or overrun fail on every
//! host: a patina run that dies of a signal the native run did not and no
//! gap of the vehicle declares is a crash, whatever the host. Every patina
//! failure, reported or failed, carries the tail of the recorded run's
//! stderr.
//!
//! A host that cannot be the oracle (a kernel lacking a covered
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

use patina_dst_conformance::catalog;
use patina_dst_conformance::compare::{Observation, Origin, Termination};
use patina_dst_conformance::host::{self, Cause};
use patina_dst_conformance::observe::parse_stream;
use std::path::Path;

#[path = "native_conformance/hang.rs"]
mod hang;
#[path = "native_conformance/leg.rs"]
mod leg;
#[path = "native_conformance/oracle.rs"]
mod oracle;
#[path = "native_conformance/process.rs"]
mod process;
#[path = "native_conformance/native_conformance.rs"]
mod scenarios;

use leg::Leg;
use oracle::{Oracle, prefixed};
use process::{logs_root, not_run, required};

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
    let oracle = Oracle::detect();
    let mut reference = None;
    let mut failures = Vec::new();
    let mut diverged = Vec::new();
    for &vehicle in scenario.vehicles {
        let leg = Leg {
            scenario,
            vehicle,
            dir: &dir,
            logs: logs.join(vehicle.name()),
            declared_absent: declared_absent.is_some(),
        };
        std::fs::create_dir_all(&leg.logs).unwrap();
        let mut leg_diverged = Vec::new();
        if let Err(leg_failures) = leg.check(oracle, &mut reference, &mut leg_diverged) {
            failures.extend(prefixed(&format!("{}: ", leg.name()), leg_failures));
        }
        diverged.extend(prefixed(&format!("{}: ", leg.name()), leg_diverged));
    }
    if !diverged.is_empty() {
        let summary = std::env::var_os("GITHUB_STEP_SUMMARY").filter(|path| !path.is_empty());
        oracle.report(
            name,
            &diverged,
            &mut std::io::stderr(),
            summary.as_deref().map(Path::new),
        );
    }
    assert!(
        failures.is_empty(),
        "{name}: {} failure(s)\n{}\nlogs: {}",
        failures.len(),
        failures.join("\n"),
        logs.display()
    );
}

/// A planted stream from `origin`: `(op, ret)` events, a check where `op` is
/// "check".
fn planted(origin: Origin, events: &[(&str, i64)], termination: Termination) -> Observation {
    let stream: String = events
        .iter()
        .enumerate()
        .map(|(seq, (op, ret))| {
            let args = if *op == "check" {
                serde_json::json!({"label": "planted"})
            } else {
                serde_json::json!({})
            };
            let event = serde_json::json!({
                "seq": seq, "op": op, "args": args, "ret": ret, "errno": null,
                "fields": {}, "norm": {},
            });
            format!("{event}\n")
        })
        .collect();
    Observation {
        origin,
        events: parse_stream(&stream).unwrap(),
        termination,
        stderr: String::new(),
    }
}
