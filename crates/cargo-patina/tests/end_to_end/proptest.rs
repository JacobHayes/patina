//! Seeded property generation and stateful/schedule shrinking.

#[cfg(test)]
mod tests {
    use super::super::*;

    // ---- proptest compatibility (patina-dst-proptest), end to end --------------------
    //
    // A whole package depending on the `patina-dst-proptest` compat crate, built and run
    // through native-build/native-run. The guest runs a proptest property whose cases
    // are generated from a `patina-dst-proptest` runner (proptest's ChaCha RNG seeded from
    // `patina_dst::rng()`), and prints a fold-digest of every generated case. Under Patina
    // that digest is a pure function of the run seed, so the same seed reproduces it,
    // a different seed changes it, and record/replay reproduces it byte-identically —
    // the determinism model that lets adopters drop proptest's regression files.

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn write_proptest_fixture(root: &Path) {
        fs::create_dir_all(root.join("src")).unwrap();
        let patina_path = native_workspace().join("crates/patina");
        let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
        let proptest_path = native_workspace().join("crates/patina-proptest");
        let proptest_path = proptest_path.to_string_lossy().replace('\\', "\\\\");
        fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"patina-dst-proptest-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst = {{ path = \"{patina_path}\" }}\npatina-dst-proptest = {{ path = \"{proptest_path}\" }}\n"
        ),
    )
    .unwrap();
        fs::write(root.join("src/main.rs"), PROPTEST_DIGEST_MAIN).unwrap();
    }

    // A passing property: with no failure proptest never shrinks, so the closure runs
    // exactly `cases` times over freshly generated inputs. Folding those inputs (and
    // the case count) produces a digest determined solely by the runner's seed, which
    // `patina-dst-proptest` draws from `patina_dst::rng()`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const PROPTEST_DIGEST_MAIN: &str = r#"
use std::cell::Cell;

use patina_dst_proptest::prelude::*;

fn case_digest() -> u64 {
    let mut runner = patina_dst_proptest::runner();
    let digest = Cell::new(0xcbf2_9ce4_8422_2325_u64);
    let cases = Cell::new(0u64);
    runner
        .run(&(any::<u64>(), 0i64..1_000_000i64), |(a, b)| {
            let mixed = a ^ (b as u64).rotate_left(21);
            digest.set(
                (digest.get() ^ mixed)
                    .wrapping_mul(0x0000_0100_0000_01b3)
                    .rotate_left(13),
            );
            cases.set(cases.get() + 1);
            Ok(())
        })
        .expect("the property holds for every generated case");
    digest.get() ^ cases.get().rotate_left(7)
}

fn main() {
    println!("PROPTEST_DIGEST digest={:016x}", case_digest());
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn proptest_digest(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.starts_with("PROPTEST_DIGEST"))
            .unwrap_or_else(|| {
                panic!(
                    "missing PROPTEST_DIGEST in stdout:\n{}",
                    String::from_utf8_lossy(&output.stdout)
                )
            })
            .to_owned()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_proptest_case_generation_is_seed_deterministic_and_replays() {
        let directory = tempdir().unwrap();
        let pkg = directory.path().join("pkg");
        write_proptest_fixture(&pkg);
        let workspace = native_workspace();
        let bin = directory.path().join("proptest-digest");
        invoke(
            workspace,
            &[
                "build",
                pkg.to_str().unwrap(),
                "--bin",
                "patina-dst-proptest-fixture",
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        // Same seed -> byte-identical case digest across two separate native-run
        // invocations; a different seed -> a different digest.
        let seeded = proptest_digest(&invoke(
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "5"],
        ));
        let repeated = proptest_digest(&invoke(
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "5"],
        ));
        let other = proptest_digest(&invoke(
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "6"],
        ));
        assert_eq!(
            seeded, repeated,
            "same seed must generate a byte-identical case digest"
        );
        assert_ne!(
            seeded, other,
            "a different seed must generate a different case digest"
        );

        // Record at seed 5, then strict replay: byte-identical digest.
        let trace = directory.path().join("proptest.patina");
        let recorded = proptest_digest(&invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "5",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "proptest-digest-v1",
            ],
        ));
        let replayed = proptest_digest(&invoke(
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "proptest-digest-v1",
            ],
        ));
        assert_eq!(recorded, seeded, "recording must not change the digest");
        assert_eq!(
            replayed, seeded,
            "strict replay must reproduce the recorded case digest byte-identically"
        );
    }

    // ---- Two-axis shrinking: stateful command-sequence + schedule ----------------
    //
    // The compose story for the model-based (stateful) layer. A package depending on
    // `patina-dst-proptest`'s state module drives a key/value store with a planted
    // off-by-one delete bug (`Remove(1)` also evicts key 0 in the SUT) against a
    // `BTreeMap` model. Two independent shrinking axes are exercised end to end:
    //
    //   * Axis 1 (input): `--find` runs the stateful runner, which searches for a
    //     failing command sequence and shrinks it. The bug pins both keys and the
    //     surviving value shrinks to 0, so it converges to one canonical minimal
    //     sequence — `[Insert(0, 0), Remove(1)]` — deterministically from the seed.
    //   * Axis 2 (schedule): `--replay-commands` re-runs exactly that minimal
    //     sequence (with a little deterministic thread interleaving so the trace
    //     carries real scheduler decisions), the run is recorded, and the existing
    //     `cargo patina minimize` path canonicalizes its schedule. The minimized
    //     artifact must still replay to the same failure marker.
    //
    // The failure is a deterministic state bug, so under strict replay the schedule
    // pass is failure-preserving without deleting decisions (the same soundness the
    // schedule-reduction e2e relies on); what this proves is that the two shrinkers
    // compose — a shrunk command sequence feeds a recorded run whose minimized trace
    // still reproduces.

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const TWO_AXIS_MAIN: &str = r#"
use std::collections::BTreeMap;

use patina_dst_proptest::prelude::*;
use patina_dst_proptest::state::{check, execute, StateMachine};

#[derive(Clone, Debug)]
enum Cmd {
    Insert(u8, u8),
    Remove(u8),
    Get(u8),
}

// Planted off-by-one delete bug: Remove(1) also evicts key 0 in the SUT while
// the model removes only key 1. The minimal counterexample is Insert(0, _) then
// Remove(1); the keys are pinned by the bug and the value shrinks to 0, so it is
// canonical across seeds: [Insert(0, 0), Remove(1)].
struct BuggyKv;

impl StateMachine for BuggyKv {
    type Command = Cmd;
    type Model = BTreeMap<u8, u8>;
    type System = BTreeMap<u8, u8>;

    fn init_model() -> Self::Model { BTreeMap::new() }
    fn init_system() -> Self::System { BTreeMap::new() }

    fn command_strategy() -> BoxedStrategy<Self::Command> {
        prop_oneof![
            (0u8..4, 0u8..4).prop_map(|(k, v)| Cmd::Insert(k, v)),
            (0u8..4).prop_map(Cmd::Remove),
            (0u8..4).prop_map(Cmd::Get),
        ]
        .boxed()
    }

    fn next(model: &mut Self::Model, command: &Self::Command) {
        match command {
            Cmd::Insert(k, v) => { model.insert(*k, *v); }
            Cmd::Remove(k) => { model.remove(k); }
            Cmd::Get(_) => {}
        }
    }

    fn apply(system: &mut Self::System, model: &Self::Model, command: &Self::Command) -> Result<(), String> {
        match command {
            Cmd::Insert(k, v) => { system.insert(*k, *v); }
            Cmd::Remove(k) => {
                system.remove(k);
                if *k == 1 { system.remove(&0); }
            }
            Cmd::Get(k) => {
                if system.get(k) != model.get(k) {
                    return Err(format!("get({k}) diverged"));
                }
            }
        }
        if system == model { Ok(()) } else {
            Err(format!("state diverged: sut={system:?} model={model:?}"))
        }
    }
}

fn token(c: &Cmd) -> String {
    match c {
        Cmd::Insert(k, v) => format!("I{k}.{v}"),
        Cmd::Remove(k) => format!("R{k}"),
        Cmd::Get(k) => format!("G{k}"),
    }
}

fn parse(spec: &str) -> Vec<Cmd> {
    spec.split(',').filter(|t| !t.is_empty()).map(|t| {
        match t.as_bytes()[0] {
            b'I' => {
                let (k, v) = t[1..].split_once('.').expect("Insert token needs key.value");
                Cmd::Insert(k.parse().unwrap(), v.parse().unwrap())
            }
            b'R' => Cmd::Remove(t[1..].parse().unwrap()),
            b'G' => Cmd::Get(t[1..].parse().unwrap()),
            other => panic!("bad token byte {other}"),
        }
    }).collect()
}

// A little deterministic thread interleaving so the recorded trace of the
// minimal-sequence run carries real scheduler decisions for the schedule
// minimization pass to engage on. It does not touch the KV state, so the planted
// failure stays a pure function of the command sequence.
fn schedule_noise() {
    use std::sync::{Arc, Mutex};
    let counter = Arc::new(Mutex::new(0u64));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let counter = Arc::clone(&counter);
            std::thread::spawn(move || {
                for _ in 0..2 {
                    let mut guard = counter.lock().unwrap();
                    *guard += 1;
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}

fn report_failure(spec: &str, commands: &[Cmd], message: &str) -> ! {
    println!("TWOAXIS_SHRUNK spec={spec} commands={commands:?}");
    println!("TWOAXIS_FAIL {message}");
    std::process::exit(7);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--find") => {
            let mut config = patina_dst_proptest::config();
            config.cases = 64;
            let mut runner = patina_dst_proptest::runner_with_config(config);
            match check::<BuggyKv>(&mut runner, 0..=16) {
                Ok(()) => println!("TWOAXIS_HELD"),
                Err(f) => {
                    let spec = f.commands.iter().map(token).collect::<Vec<_>>().join(",");
                    report_failure(&spec, &f.commands, &f.message);
                }
            }
        }
        Some("--replay-commands") => {
            let spec = args.get(1).map(String::as_str).unwrap_or("");
            schedule_noise();
            match execute::<BuggyKv>(&parse(spec)) {
                Ok(_) => println!("TWOAXIS_NO_REPRO spec={spec}"),
                Err(f) => report_failure(spec, &f.commands, &f.message),
            }
        }
        other => {
            eprintln!("usage: --find | --replay-commands <spec>; got {other:?}");
            std::process::exit(2);
        }
    }
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn write_two_axis_fixture(root: &Path) {
        fs::create_dir_all(root.join("src")).unwrap();
        let patina_path = native_workspace().join("crates/patina");
        let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
        let proptest_path = native_workspace().join("crates/patina-proptest");
        let proptest_path = proptest_path.to_string_lossy().replace('\\', "\\\\");
        fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"two-axis-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst = {{ path = \"{patina_path}\" }}\npatina-dst-proptest = {{ path = \"{proptest_path}\" }}\n"
        ),
    )
    .unwrap();
        fs::write(root.join("src/main.rs"), TWO_AXIS_MAIN).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn two_axis_shrunk_line(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.starts_with("TWOAXIS_SHRUNK"))
            .unwrap_or_else(|| {
                panic!(
                    "missing TWOAXIS_SHRUNK in stdout:\n{}",
                    String::from_utf8_lossy(&output.stdout)
                )
            })
            .to_owned()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn two_axis_replay_oracle(exe: &Path, bin: &Path, spec: &str) -> String {
        format!(
            "#!/bin/sh\nout=$(\"{}\" replay \"{}\" \"$PATINA_MINIMIZE_TRACE\" -- --replay-commands \"{}\" 2>/dev/null)\ncode=$?\nif [ \"$code\" -eq 7 ] && printf '%s' \"$out\" | grep -q 'TWOAXIS_FAIL'; then\n  exit 1\nfi\nexit 0\n",
            exe.display(),
            bin.display(),
            spec
        )
    }

    // Class detector: an oracle must not preserve infrastructure/replay failures
    // merely because the guest printed its marker before the later refusal.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn two_axis_replay_oracle_requires_exact_failure_code_and_marker() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let fake = dir.path().join("replay");
        fs::write(
            &fake,
            "#!/bin/sh\nprintf '%s\\n' \"$TEST_MARKER\"\nexit \"$TEST_CODE\"\n",
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let oracle = dir.path().join("oracle.sh");
        fs::write(
            &oracle,
            two_axis_replay_oracle(&fake, Path::new("guest"), "I0.0,R1"),
        )
        .unwrap();
        for code in [0, 1, 7, 134] {
            for marker in ["", "TWOAXIS_FAIL planted failure"] {
                let status = Command::new("/bin/sh")
                    .arg(&oracle)
                    .env("TEST_CODE", code.to_string())
                    .env("TEST_MARKER", marker)
                    .status()
                    .unwrap();
                let expected = i32::from(code == 7 && !marker.is_empty());
                assert_eq!(
                    status.code(),
                    Some(expected),
                    "code={code}, marker={marker:?}"
                );
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_two_axis_stateful_shrink_then_schedule_minimize() {
        let directory = tempdir().unwrap();
        let pkg = directory.path().join("pkg");
        write_two_axis_fixture(&pkg);
        let workspace = native_workspace();
        let bin = directory.path().join("two-axis");
        invoke(
            workspace,
            &[
                "build",
                pkg.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let exe = env!("CARGO_BIN_EXE_cargo-patina");

        // --- Axis 1: the stateful shrinker finds and minimizes the failing command
        // sequence. The planted bug reproduces at essentially every seed; sweep for
        // the first that exits with the failure code.
        let mut found = None;
        for seed in 0..8u64 {
            let out = invoke_unchecked(
                exe,
                workspace,
                &[
                    "run",
                    bin.to_str().unwrap(),
                    "--seed",
                    &seed.to_string(),
                    "--",
                    "--find",
                ],
            );
            if out.status.code() == Some(7) {
                found = Some((seed, two_axis_shrunk_line(&out)));
                break;
            }
        }
        let (seed, shrunk) = found.expect("no seed in 0..8 reproduced the planted state bug");
        let seed_string = seed.to_string();
        assert_eq!(
            shrunk, "TWOAXIS_SHRUNK spec=I0.0,R1 commands=[Insert(0, 0), Remove(1)]",
            "the stateful shrinker must converge to the canonical minimal sequence"
        );

        // Stable across a repeated run at the same seed.
        let repeat = invoke_unchecked(
            exe,
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                &seed_string,
                "--",
                "--find",
            ],
        );
        assert_eq!(
            two_axis_shrunk_line(&repeat),
            shrunk,
            "the shrunk command sequence must be stable across repeats"
        );

        let spec = "I0.0,R1";

        // --- Axis 2: record the shrunk failing run, minimize its schedule, and
        // replay the minimized artifact — it must still fail with the same marker.
        let trace = directory.path().join("fail.patina");
        let recorded = invoke_unchecked(
            exe,
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                &seed_string,
                "--record",
                trace.to_str().unwrap(),
                "--",
                "--replay-commands",
                spec,
            ],
        );
        assert_eq!(
            recorded.status.code(),
            Some(7),
            "recording the minimal-sequence run must reproduce the failure:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&recorded.stderr)
        );
        assert!(String::from_utf8_lossy(&recorded.stdout).contains("TWOAXIS_FAIL"));
        // Separate strict replay soundness from the schedule oracle's verdict.
        let original_replay = invoke_unchecked(
            exe,
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--",
                "--replay-commands",
                spec,
            ],
        );
        assert_eq!(
            original_replay.status.code(),
            Some(7),
            "original replay: {}",
            String::from_utf8_lossy(&original_replay.stderr)
        );

        // Class pairing: two_axis_replay_oracle_requires_exact_failure_code_and_marker.
        // Reject a later replay abort even if the guest already printed the marker.
        let oracle = directory.path().join("oracle.sh");
        fs::write(&oracle, two_axis_replay_oracle(Path::new(exe), &bin, spec)).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&oracle, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let minimized_path = directory.path().join("fail-min.patina");
        let minimized = invoke(
            workspace,
            &[
                "minimize",
                trace.to_str().unwrap(),
                "--output",
                minimized_path.to_str().unwrap(),
                "--",
                oracle.to_str().unwrap(),
            ],
        );
        assert!(
            String::from_utf8_lossy(&minimized.stdout).contains("PATINA_MINIMIZE_COMPLETE"),
            "missing minimize completion line:\n{}",
            String::from_utf8_lossy(&minimized.stdout)
        );

        // The minimized trace must still replay to the same failure marker.
        let replayed = invoke_unchecked(
            exe,
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                minimized_path.to_str().unwrap(),
                "--",
                "--replay-commands",
                spec,
            ],
        );
        assert_eq!(
            replayed.status.code(),
            Some(7),
            "minimized trace no longer reproduces the failure:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&replayed.stdout),
            String::from_utf8_lossy(&replayed.stderr)
        );
        assert!(
            String::from_utf8_lossy(&replayed.stdout).contains("TWOAXIS_FAIL"),
            "minimized replay must carry the same failure marker"
        );
    }
}
