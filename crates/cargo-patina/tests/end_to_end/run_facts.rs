//! Runtime-owned envelope facts, refusal attribution, and liveness, and the
//! native outcome guest other campaign tests share.

use super::*;

/// The binary `build` produces in the directory it is given, built once per
/// nextest run under this test build's target base and shared by every test
/// that names it.
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
/// once per nextest run through `patina build` and shared by name.
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
    // Outcome channel: the `patina.result/v2`
    // envelope's runtime-owned facts. `fault_reports`/`runtime_findings` come from
    // the runtime's own `patina.runfacts/v1` document — the same report structs the
    // `PATINA_*_REPORT` lines are formatted from — while `refusal`/`guest_exit` are
    // constructed by the supervising process, which is all a dying child leaves it.
    // ---------------------------------------------------------------------------

    /// Parse the whitespace-delimited `k=v` fields of a `PATINA_*` report line. Used
    /// ONLY by the test, to prove the structured plane and the printed line describe
    /// the same run — patina itself never reads a line back.
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

    /// The envelope of `patina <arguments>`, whatever its exit status.
    fn envelope(arguments: &[&str]) -> serde_json::Value {
        let output = invoke_with_deadline(
            env!("CARGO_BIN_EXE_patina"),
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
            faulted["reports"].as_str().unwrap(),
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
            "--liveness-watchdog",
            "1000000000",
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
        assert_eq!(
            (
                &wedged["result"],
                &wedged["attribution"],
                &wedged["exit_code"]
            ),
            (&"liveness".into(), &"guest".into(), &1.into()),
            "a liveness wedge is a finding about the guest, not patina refusing:\n{wedged:#}"
        );

        // The guest's own abort: structurally a signal death, and deliberately NOT
        // a patina refusal, which is what lets a classifier file it as a finding.
        let aborted = envelope(&[
            "run", guest, "--seed", "1", "--format", "json", "--", "abort",
        ]);
        assert_eq!(aborted["guest_exit"]["signal"], 6);
        assert_eq!(aborted["guest_exit"]["signal_name"], "SIGABRT");
        assert_eq!(
            (
                &aborted["result"],
                &aborted["attribution"],
                &aborted["exit_code"]
            ),
            (&"crash".into(), &"guest".into(), &1.into()),
            "a guest's own abort is the guest's, never patina's:\n{aborted:#}"
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
        let tampered = recorded.replace("\"patina-native\"", "\"patina-native+instrumented\"");
        assert_ne!(
            recorded, tampered,
            "the trace fingerprint was not rewritten"
        );
        fs::write(&trace, tampered).unwrap();
        let refused = envelope(&["replay", guest, trace.to_str().unwrap(), "--format", "json"]);
        // The trace does not fit this run: the request's, named by the stop
        // the runtime's own refusal left, and never the guest's abort.
        assert_eq!(
            (
                &refused["result"],
                &refused["attribution"],
                &refused["exit_code"]
            ),
            (&"error".into(), &"request".into(), &2.into()),
            "a refused trace must be attributed to the request:\n{refused:#}"
        );
        assert_eq!(refused["stop"]["reason"], "runtime_init", "{refused:#}");
        assert!(
            !refused["stop"]["detail"].as_str().unwrap().is_empty(),
            "the stop must carry the line that announced it:\n{refused:#}"
        );
        assert_eq!(refused["guest_exit"]["signal_name"], "SIGABRT");
    }

    /// A Rust backtrace symbolizes against the guest's own executable, which
    /// it finds through procfs. A panic under `RUST_BACKTRACE=1` either names
    /// the panicking function in its frames or the run says, structurally,
    /// that the executable was not there to read; a run that never looks for
    /// it says nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_backtrace_names_its_frames_or_the_run_says_why_not() {
        const FRAME: &str = "backtrace_probe_frame";
        let source = format!(
            r#"
#[inline(never)]
fn {FRAME}(panic: bool) {{
    if panic {{ panic!("asked to"); }}
}}
fn main() {{
    {FRAME}(std::hint::black_box(std::env::args().nth(1).is_some()));
}}
"#
        );
        let guest = super::shared_guest("backtrace-guest", |directory| {
            build_facts_guest(directory, "backtrace", &source)
        });
        let guest = guest.to_str().unwrap();
        let run = |extra: &[&str]| {
            let mut arguments = vec![
                "run",
                guest,
                "--env",
                "RUST_BACKTRACE=1",
                "--format",
                "json",
            ];
            arguments.extend_from_slice(extra);
            envelope(&arguments)
        };

        let panicked = run(&["--", "panic"]);
        assert_eq!(panicked["result"], "failure", "{panicked:#}");
        let stderr = panicked["stderr"].as_str().unwrap();
        let named = stderr
            .split_once("stack backtrace:")
            .is_some_and(|(_, frames)| frames.contains(FRAME));
        assert!(
            named || panicked["executable_unavailable"] == true,
            "the backtrace names no frame and the run does not say why:\n{panicked:#}"
        );

        let clean = run(&[]);
        assert_eq!(clean["result"], "ok", "{clean:#}");
        assert!(clean["executable_unavailable"].is_null(), "{clean:#}");
    }

    /// A run that fails because the guest read a host path the simulated
    /// filesystem was never given says so beside its class: the class and
    /// the exit status are the failure's, and `likely_artifacts` names the
    /// path and the `--mount` that provides it. That mount, at the directory's
    /// own path, makes the run pass and replays; a path the host lacks too,
    /// and a run that read nothing missing, carry no such entry.
    #[test]
    fn a_host_path_the_run_was_not_given_is_a_likely_artifact() {
        let source = r#"
fn main() {
    let path = std::env::args().nth(1).expect("a path to read");
    let text = std::fs::read_to_string(&path).expect("the fixture is readable");
    assert_eq!(text, "fixture\n");
}
"#;
        let guest = super::shared_guest("host-path-guest", |directory| {
            build_facts_guest(directory, "host_path", source)
        });
        let guest = guest.to_str().unwrap();
        let host = tempdir().unwrap();
        let fixtures = fs::canonicalize(host.path()).unwrap().join("fixtures");
        fs::create_dir(&fixtures).unwrap();
        let fixture = fixtures.join("data.txt");
        fs::write(&fixture, "fixture\n").unwrap();
        let (fixtures, fixture) = (fixtures.to_str().unwrap(), fixture.to_str().unwrap());
        let own_path = format!("{fixtures}:{fixtures}");
        let run = |arguments: &[&str]| {
            let output = invoke_with_deadline(
                env!("CARGO_BIN_EXE_patina"),
                native_workspace(),
                arguments,
                Duration::from_secs(20),
            )
            .expect("the run terminates");
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|error| {
                    panic!("{error}:\n{}", String::from_utf8_lossy(&output.stderr))
                });
            assert_eq!(
                output.status.code(),
                envelope["exit_code"].as_i64().map(|code| code as i32),
                "{envelope:#}"
            );
            envelope
        };
        let artifacts = |envelope: &serde_json::Value| -> Vec<(String, String)> {
            envelope["likely_artifacts"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|artifact| {
                    let field = |key| artifact[key].as_str().unwrap_or_default().to_string();
                    (field("kind"), field("path"))
                })
                .collect()
        };

        let unmounted = run(&["run", guest, "--format", "json", "--", fixture]);
        assert_eq!(unmounted["result"], "failure", "{unmounted:#}");
        assert_eq!(unmounted["exit_code"], 1, "{unmounted:#}");
        assert_eq!(
            artifacts(&unmounted),
            [("missing_host_path".to_string(), fixture.to_string())],
            "{unmounted:#}"
        );
        assert_eq!(unmounted["likely_artifacts"][0]["mount"], own_path);

        // Mounted at `/`, the corpus is there under another name: the path
        // the guest named is still one it was not given.
        let at_root = run(&[
            "run", guest, "--format", "json", "--mount", fixtures, "--", fixture,
        ]);
        assert_eq!(at_root["result"], "failure", "{at_root:#}");
        assert_eq!(artifacts(&at_root), artifacts(&unmounted), "{at_root:#}");

        let absent = format!("{fixtures}/absent.txt");
        let nowhere = run(&["run", guest, "--format", "json", "--", &absent]);
        assert_eq!(nowhere["result"], "failure", "{nowhere:#}");
        assert!(nowhere["likely_artifacts"].is_null(), "{nowhere:#}");

        let trace_dir = tempdir().unwrap();
        let trace = trace_dir.path().join("mounted.patina");
        let trace = trace.to_str().unwrap();
        let mounted = run(&[
            "run", guest, "--format", "json", "--mount", &own_path, "--record", trace, "--",
            fixture,
        ]);
        assert_eq!(mounted["result"], "ok", "{mounted:#}");
        assert!(mounted["likely_artifacts"].is_null(), "{mounted:#}");
        let replayed = run(&[
            "replay", guest, trace, "--format", "json", "--mount", &own_path,
        ]);
        assert_eq!(replayed["result"], "ok", "{replayed:#}");
        // The guest directory is part of the corpus a trace pins.
        let elsewhere = format!("{fixtures}:/elsewhere");
        let moved = run(&[
            "replay", guest, trace, "--format", "json", "--mount", &elsewhere,
        ]);
        assert_eq!(moved["result"], "error", "{moved:#}");
        assert_eq!(moved["stop"]["mismatch"], "mount_contents", "{moved:#}");
    }
}
