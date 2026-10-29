//! Runtime-owned envelope facts, refusal attribution, and liveness, and the
//! native outcome guest other campaign tests share.

use super::*;

/// The binary `build` produces in the directory it is given, built once per
/// nextest run under this test build's target base and shared by every test
/// that names it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn shared_guest(name: &str, build: impl FnOnce(&Path) -> PathBuf) -> PathBuf {
    static IN_PROCESS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serial = IN_PROCESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    common::once_per_run(name, || {
        let directory = common::guest_target_dir(name);
        fs::create_dir_all(&directory).unwrap();
        vec![build(&directory)]
    })
    .remove(0)
}

/// An SDK guest package (`patina-dst` dependency, `main` as its source) built
/// once per nextest run through `cargo patina build` and shared by name.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn shared_sdk_guest(name: &str, main: &str) -> PathBuf {
    shared_guest(name, |directory| {
        let package = directory.join("pkg");
        write_sdk_fixture(&package, main);
        // The package sits under the workspace's target base, so it declares
        // its own workspace root.
        let manifest = package.join("Cargo.toml");
        let mut contents = fs::read_to_string(&manifest).unwrap();
        contents.push_str("\n[workspace]\n");
        fs::write(&manifest, contents).unwrap();
        let binary = directory.join(name);
        invoke(
            native_workspace(),
            &[
                "build",
                package.to_str().unwrap(),
                "--output",
                binary.to_str().unwrap(),
            ],
        );
        binary
    })
}

/// A native guest whose first argument picks an outcome:
///
/// * none: forty filesystem writes, giving the fs fault knobs eligible traffic;
/// * `abort`: abort on the guest's own invariant, printing nothing patina owns;
/// * `wedge`: churn on virtual time without progress, for the liveness watchdog;
/// * `wide`: write streams well past a pipe buffer (64 KiB on Linux, at most
///   that on macOS), so a `--format json` envelope is one ~200 KiB line;
/// * `level-one`: exit 0 after printing a failure only the guest's own dialect
///   names.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const OUTCOME_SOURCE: &str = r#"
use std::time::Duration;

fn main() {
    match std::env::args().nth(1).as_deref() {
        None => {
            let mut ok = 0u32;
            let mut errs = 0u32;
            for index in 0..40u32 {
                match std::fs::write(format!("/entry-{index}"), b"payload") {
                    Ok(()) => ok += 1,
                    Err(_) => errs += 1,
                }
            }
            println!("PATINA_RESULT ok={ok} errs={errs}");
        }
        Some("abort") => {
            println!("APP_INVARIANT_BROKEN detail=ledger-does-not-balance");
            std::process::abort();
        }
        Some("wedge") => {
            for _ in 0..10_000 {
                std::thread::sleep(Duration::from_millis(1));
            }
            println!("PATINA_RESULT unreachable=1");
        }
        Some("wide") => {
            let line = "w".repeat(1023);
            for _ in 0..200 {
                eprintln!("{line}");
            }
            println!("WIDE_OUT done");
        }
        Some("level-one") => println!("GUEST: checksum mismatch on page 7"),
        Some(other) => panic!("unknown mode {other:?}"),
    }
}
"#;

/// The [`OUTCOME_SOURCE`] guest.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn outcome_guest() -> PathBuf {
    shared_guest("outcome-guest", |directory| {
        build_facts_guest(directory, "outcome", OUTCOME_SOURCE)
    })
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::outcome_guest;

    // ---------------------------------------------------------------------------
    // Outcome channel: the `patina.result/v1`
    // envelope's runtime-owned facts. `fault_reports`/`runtime_findings` come from
    // the runtime's own `patina.runfacts/v1` document — the same report structs the
    // `PATINA_*_REPORT` lines are formatted from — while `refusal`/`guest_exit` are
    // constructed by the supervising process, which is all a dying child leaves it.
    // ---------------------------------------------------------------------------

    /// Parse the whitespace-delimited `k=v` fields of a `PATINA_*` report line. Used
    /// ONLY by the test, to prove the structured plane and the printed line describe
    /// the same run — patina itself never reads a line back.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn report_line_fields(stderr: &str, marker: &str) -> BTreeMap<String, String> {
        let line = stderr
            .lines()
            .find(|line| line.trim_start().starts_with(marker))
            .unwrap_or_else(|| panic!("missing {marker} line:\n{stderr}"));
        line.split_whitespace()
            .skip(1)
            .filter_map(|token| token.split_once('='))
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    /// The envelope of `cargo patina <arguments>`, whatever its exit status.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn envelope(arguments: &[&str]) -> serde_json::Value {
        let output = invoke_with_deadline(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            arguments,
            Duration::from_secs(20),
        )
        .expect("the run must terminate, not deadlock in its diagnostic");
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "no JSON envelope: {error}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }

    /// The envelope carries the fault planes and runtime findings the runtime
    /// owns, a liveness finding survives the abort that follows it, and a
    /// refusal is attributed only when patina refused: a guest's own abort is
    /// a signal death with no refusal.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_envelope_carries_runtime_facts_and_attributes_only_patinas_refusals() {
        let guest = outcome_guest();
        let guest = guest.to_str().unwrap();

        let faulted = envelope(&[
            "run",
            guest,
            "--seed",
            "7",
            "--fs-error-permille",
            "300",
            "--format",
            "json",
        ]);
        assert_eq!(faulted["result"], "ok", "{faulted:#}");
        let plane = &faulted["fault_reports"]["fs"];
        assert!(
            !plane.is_null(),
            "the fs plane must reach the envelope:\n{faulted:#}"
        );
        // The structured plane and the human line describe the same run, field for
        // field — including the per-op-kind breakdown and the vacuity bit.
        let printed = report_line_fields(
            faulted["stderr"].as_str().unwrap(),
            "PATINA_FS_FAULT_REPORT",
        );
        assert_eq!(
            plane["eligible_ops"].as_u64().unwrap().to_string(),
            printed["eligible_ops"]
        );
        assert_eq!(
            plane["errors_injected"].as_u64().unwrap().to_string(),
            printed["errors_injected"]
        );
        assert_eq!(
            u8::from(plane["vacuous"].as_bool().unwrap()).to_string(),
            printed["vacuous"]
        );
        assert!(
            plane["errors_injected"].as_u64().unwrap() > 0,
            "the error knob must have fired for this run to prove anything:\n{faulted:#}"
        );
        let structured_kinds: BTreeMap<String, String> = plane["errors_by_op"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(kind, count)| (kind.clone(), count.to_string()))
            .collect();
        let printed_kinds: BTreeMap<String, String> = printed["errors_by_op"]
            .split(',')
            .filter_map(|token| token.split_once(':'))
            .map(|(kind, count)| (kind.to_string(), count.to_string()))
            .collect();
        assert_eq!(structured_kinds, printed_kinds);

        // The watchdog fires mid-run and the shim aborts the process, so `finish`
        // — where the facts document is normally written — never runs. The
        // finding survives anyway.
        let wedged = envelope(&[
            "run",
            guest,
            "--seed",
            "1",
            "--liveness-watchdog=1000000000",
            "--format",
            "json",
            "--",
            "wedge",
        ]);
        let liveness = wedged["runtime_findings"]
            .as_array()
            .unwrap_or_else(|| panic!("no runtime findings:\n{wedged:#}"))
            .iter()
            .find(|finding| finding["source"] == "liveness")
            .unwrap_or_else(|| panic!("no liveness finding:\n{wedged:#}"));
        assert_eq!(liveness["kind"], "liveness");
        assert_eq!(liveness["detail"], "no-progress");
        let printed = report_line_fields(wedged["stderr"].as_str().unwrap(), "PATINA_VIOLATION");
        assert_eq!(
            liveness["budget_ns"].as_u64().unwrap().to_string(),
            printed["budget_ns"]
        );
        assert_eq!(
            liveness["vtime_ns"].as_u64().unwrap().to_string(),
            printed["vtime_ns"]
        );
        assert!(
            wedged.get("refusal").is_none(),
            "a liveness wedge is a finding about the guest, not patina refusing:\n{wedged:#}"
        );

        // The guest's own abort: structurally a signal death, and deliberately NOT
        // a patina refusal, which is what lets a classifier file it as a finding.
        let aborted = envelope(&[
            "run", guest, "--seed", "1", "--format", "json", "--", "abort",
        ]);
        assert_eq!(aborted["guest_exit"]["signal"], 6);
        assert_eq!(aborted["guest_exit"]["signal_name"], "SIGABRT");
        assert!(
            aborted.get("refusal").is_none(),
            "a guest's own abort must carry no patina refusal:\n{aborted:#}"
        );

        // Patina refusing is attributed by class. A trace whose recorded
        // fingerprint does not match the runtime's is the canonical case.
        let directory = tempdir().unwrap();
        let trace = directory.path().join("refusal.patina");
        invoke(
            native_workspace(),
            &[
                "run",
                guest,
                "--seed",
                "7",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let recorded = fs::read_to_string(&trace).unwrap();
        let tampered = recorded.replace("\"patina-native\"", "\"patina-native+yieldpoints\"");
        assert_ne!(
            recorded, tampered,
            "the trace fingerprint was not rewritten"
        );
        fs::write(&trace, tampered).unwrap();
        let refused = envelope(&["replay", guest, trace.to_str().unwrap(), "--format", "json"]);
        assert_eq!(
            refused["refusal"]["class"], "fingerprint_mismatch",
            "patina's own refusal must be attributed:\n{refused:#}"
        );
        assert!(
            refused["refusal"]["message"]
                .as_str()
                .unwrap()
                .contains("fingerprint mismatch"),
            "the refusal must carry the line that announced it:\n{refused:#}"
        );
        assert_eq!(refused["guest_exit"]["signal_name"], "SIGABRT");
    }
}
