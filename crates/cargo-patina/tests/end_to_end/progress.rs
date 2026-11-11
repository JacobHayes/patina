//! `--progress`: under `--format json`, progress events on stderr as JSON
//! Lines, while stdout still carries exactly one result.

#[cfg(test)]
mod tests {
    use super::super::*;

    /// A campaign guest that fails on about half its seeds, so the stream
    /// carries failures and a novel signature as well as clean generations.
    const HALF_FAILING_GUEST: &str = "use std::hash::{BuildHasher, Hasher};\n\
        fn main() {\n\
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();\n\
        hasher.write_u8(0);\n\
        if hasher.finish() % 2 == 0 { panic!(\"half the seeds\"); }\n\
        }\n";

    /// The `generation` events of a campaign's progress stream: the counts
    /// only grow, and the last event is the target the envelope reports.
    #[test]
    fn campaign_progress_counts_climb_to_the_target_beside_one_envelope() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("half.rs");
        fs::write(&source, HALF_FAILING_GUEST).unwrap();
        let out = directory.path().join("campaign");
        // The request comes from the environment default, which the
        // campaign's `patina run` children must not inherit.
        let output = Command::new(env!("CARGO_BIN_EXE_patina"))
            .current_dir(native_workspace())
            .args(["campaign", source.to_str().unwrap()])
            .args(["--gens", "6", "--progress-every", "4", "--format", "json"])
            .arg("--out-dir")
            .arg(&out)
            .env("PATINA_PROGRESS", "1")
            .output()
            .unwrap();
        let envelope = campaign_json_stdout(&output);
        let events = progress_events(&output, "campaign");
        let generations: Vec<&serde_json::Value> = events
            .iter()
            .filter(|event| event["event"] == "generation")
            .collect();
        assert!(!generations.is_empty(), "{events:#?}");
        for pair in generations.windows(2) {
            let (before, after) = (pair[0], pair[1]);
            assert!(
                before["done"].as_u64() < after["done"].as_u64(),
                "{pair:#?}"
            );
            for count in ["failures", "novel_signatures"] {
                assert!(
                    before[count].as_u64() <= after[count].as_u64(),
                    "{count}: {pair:#?}"
                );
            }
        }
        let last = generations.last().unwrap();
        assert!(
            generations
                .iter()
                .all(|event| event["target"] == envelope["generations"]),
            "{generations:#?}"
        );
        assert_eq!(last["done"], envelope["generations"], "{last:#}");
        for count in ["failures", "novel_signatures", "classes"] {
            assert_eq!(
                last[count], envelope[count],
                "{count}: {last:#}\n{envelope:#}"
            );
        }
        assert!(
            envelope["failures"].as_u64() > Some(0),
            "the guest is meant to fail some generations: {envelope:#}"
        );
    }

    /// A run reports its build and then its start, and a run asked for no
    /// progress writes none.
    #[test]
    fn run_progress_reports_build_then_run_beside_one_envelope() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("hello.rs");
        fs::write(&source, "fn main() { println!(\"hello\"); }\n").unwrap();
        let run = |extra: &[&str]| {
            invoke_unchecked(
                env!("CARGO_BIN_EXE_patina"),
                native_workspace(),
                &[
                    &["run", source.to_str().unwrap(), "--format", "json"][..],
                    extra,
                ]
                .concat(),
            )
        };
        let output = run(&["--progress"]);
        let envelope = single_envelope(&output);
        assert_eq!(envelope["result"], "ok", "{envelope:#}");
        let events = progress_events(&output, "run");
        let position = |name: &str| {
            events
                .iter()
                .position(|event| event["event"] == name)
                .unwrap_or_else(|| panic!("no {name} event: {events:#?}"))
        };
        assert!(position("build_started") < position("build_finished"));
        assert!(position("build_finished") < position("run_started"));

        let quiet = run(&[]);
        single_envelope(&quiet);
        assert!(
            progress_events(&quiet, "run").is_empty(),
            "progress is opt-in"
        );
    }
}
