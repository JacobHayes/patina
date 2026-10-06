//! Recording equivalence, killed-native IPC cleanup, and planted syscall leaks.

use super::*;
use crate::process::logs_root;
use std::os::unix::process::ExitStatusExt;

/// Recording changes nothing a run observes: the legs judge only the
/// recorded patina run, so a plain run of the same seed must match it event
/// for event and in its ending. One filesystem, one network and one signal
/// scenario, through their first vehicle.
#[test]
fn recording_changes_no_observation() {
    for name in ["fs/rw", "net/tcp", "signal/basic"] {
        let scenario = catalog::scenario(name).unwrap();
        let owned = tempfile::Builder::new()
            .prefix("patina-conformance-")
            .tempdir()
            .unwrap();
        let logs = logs_root().join("recording").join(name.replace('/', "-"));
        let _ = std::fs::remove_dir_all(&logs);
        std::fs::create_dir_all(&logs).unwrap();
        let leg = Leg {
            scenario,
            vehicle: scenario.vehicles[0],
            dir: &owned.path().join("run"),
            logs,
            declared_absent: false,
        };
        let plain = leg.patina(None).unwrap();
        let recorded = leg.patina(Some(&leg.logs.join("run.patina"))).unwrap();
        assert!(
            !plain.events.is_empty(),
            "{name}: no events\n{}",
            plain.stderr
        );
        assert_eq!(plain.events, recorded.events, "{name}");
        assert_eq!(plain.termination, recorded.termination, "{name}");
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
        let needs_keys = scenario.needs.contains(&Need::Keys);
        // SAFETY: the hook only calls async-signal-safe libc functions.
        unsafe { command.pre_exec(move || pin_process_state(needs_keys)) };
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
    // A copy aimed at another process: the self-copy allowance must not
    // cover it, in either filter.
    let foreign = |line: &str| line.starts_with("process_vm_readv(1,");
    assert!(
        escaped.iter().any(|line| foreign(line)),
        "the planted foreign-pid copy was not flagged: {escaped:?}"
    );
    let awk = Command::new("awk")
        .arg("-f")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testbeds/native-boundary/containment.awk"),
        )
        .arg(&log)
        .output()
        .unwrap();
    assert!(awk.status.success(), "{}", text(&awk.stderr));
    let flagged = text(&awk.stdout);
    assert!(
        flagged.lines().any(foreign),
        "containment.awk did not flag the planted foreign-pid copy: {flagged}"
    );
}
