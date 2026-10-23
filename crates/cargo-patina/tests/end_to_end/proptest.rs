//! Seeded property generation and stateful/schedule shrinking.

#[cfg(test)]
mod tests {
    use super::super::*;
    use common::native::{Guest, assert_success};

    // ---- proptest compatibility (patina-dst-proptest), end to end --------------------
    //
    // One package depending on the `patina-dst-proptest` compat crate, built and run
    // through native-build/native-run. With no arguments the guest runs a passing
    // proptest property whose cases are generated from a `patina-dst-proptest`
    // runner (proptest's ChaCha RNG seeded from `patina_dst::rng()`), and prints a
    // fold-digest of every generated case: with no failure proptest never shrinks,
    // so the digest is a pure function of the run seed. That is the determinism
    // model that lets adopters drop proptest's regression files.
    //
    // `--find` and `--replay-commands` drive the stateful layer: a key/value store
    // with a planted off-by-one delete bug (`Remove(1)` also evicts key 0 in the
    // SUT) against a `BTreeMap` model, for the two-axis shrinking test below.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const PROPTEST_MAIN: &str = r#"
use std::cell::Cell;
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
        None => println!("PROPTEST_DIGEST digest={:016x}", case_digest()),
        other => {
            eprintln!("usage: [--find | --replay-commands <spec>]; got {other:?}");
            std::process::exit(2);
        }
    }
}
"#;

    /// The proptest guest package, built once.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn proptest_guest() -> Guest {
        let dir = tempdir().unwrap();
        let root = dir.path().join("pkg");
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
        fs::write(root.join("src/main.rs"), PROPTEST_MAIN).unwrap();
        let binary = dir.path().join("proptest-guest");
        invoke(
            native_workspace(),
            &[
                "build",
                root.to_str().unwrap(),
                "--output",
                binary.to_str().unwrap(),
            ],
        );
        Guest { dir, binary }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn line_with<'a>(output: &'a Output, prefix: &str) -> &'a str {
        std::str::from_utf8(&output.stdout)
            .unwrap()
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| {
                panic!(
                    "missing {prefix} in stdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })
    }

    /// The replay oracle `cargo patina minimize` runs per candidate: a candidate
    /// keeps the failure only when its replay exits with the failure's exact code
    /// AND prints the marker, so an infrastructure or replay failure after the
    /// guest printed its marker is not mistaken for the failure.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn two_axis_replay_oracle(exe: &Path, bin: &Path, spec: &str) -> String {
        format!(
            "#!/bin/sh\nout=$(\"{}\" replay \"{}\" \"$PATINA_MINIMIZE_TRACE\" -- --replay-commands \"{}\" 2>/dev/null)\ncode=$?\nif [ \"$code\" -eq 7 ] && printf '%s' \"$out\" | grep -q 'TWOAXIS_FAIL'; then\n  exit 1\nfi\nexit 0\n",
            exe.display(),
            bin.display(),
            spec
        )
    }

    // Two independent shrinking axes, end to end, after the seed model of case
    // generation:
    //
    //   * Seeds: the case digest is deterministic per seed (the shared run check
    //     records, repeats and replays it) and a different seed changes it.
    //   * Axis 1 (input): `--find` runs the stateful runner, which searches for a
    //     failing command sequence and shrinks it. The bug pins both keys and the
    //     surviving value shrinks to 0, so it converges to one canonical minimal
    //     sequence — `[Insert(0, 0), Remove(1)]` — deterministically from the seed.
    //   * Axis 2 (schedule): `--replay-commands` re-runs exactly that minimal
    //     sequence (with a little deterministic thread interleaving so the trace
    //     carries real scheduler decisions), the run is recorded, and
    //     `cargo patina minimize` canonicalizes its schedule through a replay
    //     oracle. The minimized artifact must still replay to the same failure.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_proptest_generates_per_seed_and_shrinks_input_then_schedule() {
        let guest = proptest_guest();
        let digest = guest.assert_run_success(5, &[]);
        let other = assert_success(guest.command("run", &["--seed", "6"]));
        assert_ne!(
            line_with(&digest, "PROPTEST_DIGEST"),
            line_with(&other, "PROPTEST_DIGEST"),
            "a different seed must generate a different case digest"
        );

        let workspace = native_workspace();
        let exe = env!("CARGO_BIN_EXE_cargo-patina");
        let bin = guest.binary.to_str().unwrap();

        // --- Axis 1: the stateful shrinker finds and minimizes the failing command
        // sequence. The planted bug reproduces at essentially every seed; sweep for
        // the first that exits with the failure code.
        let (seed, shrunk) = (0..8u64)
            .find_map(|seed| {
                let out = guest.command("run", &["--seed", &seed.to_string(), "--", "--find"]);
                (out.status.code() == Some(7))
                    .then(|| (seed, line_with(&out, "TWOAXIS_SHRUNK").to_owned()))
            })
            .expect("no seed in 0..8 reproduced the planted state bug");
        // An exact sequence, so a shrinker that wandered between runs would not
        // land on it every time.
        assert_eq!(
            shrunk, "TWOAXIS_SHRUNK spec=I0.0,R1 commands=[Insert(0, 0), Remove(1)]",
            "the stateful shrinker must converge to the canonical minimal sequence"
        );
        let spec = "I0.0,R1";

        // --- Axis 2: record the shrunk failing run, minimize its schedule, and
        // replay the minimized artifact — it must still fail with the same marker.
        let trace = guest.dir.path().join("fail.patina");
        let recorded = guest.command(
            "run",
            &[
                "--seed",
                &seed.to_string(),
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
        line_with(&recorded, "TWOAXIS_FAIL");

        let oracle = guest.dir.path().join("oracle.sh");
        fs::write(
            &oracle,
            two_axis_replay_oracle(Path::new(exe), &guest.binary, spec),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&oracle, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let minimized_path = guest.dir.path().join("fail-min.patina");
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
                bin,
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
        line_with(&replayed, "TWOAXIS_FAIL");
    }
}
