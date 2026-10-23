//! Guided campaign steering, novelty, deterministic continuation, and vacuity.

#[cfg(test)]
mod tests {
    use super::super::*;

    // ---------------------------------------------------------------------------
    // Coverage-guided generation scheduling (coverage-depth arc, wave E).
    // ---------------------------------------------------------------------------

    // Guidance must satisfy two claims at once, and each one is the other's trap: it
    // has to CHANGE the generation stream (or the mode is an inert knob, and a clean
    // guided campaign would say nothing about guidance), and it has to stay a pure
    // function of (seed base, persisted novelty log) so a guided campaign is still
    // reproducible. Asserting only the first would pass for a nondeterministic
    // scheduler; asserting only the second would pass for a no-op.
    //
    // The repeat is a campaign that runs the first generations fresh, survives a
    // checkpoint tear, and runs the rest through `--extend`. An extended guided
    // campaign re-derives generation k from the PERSISTED novelty log rather than
    // from loop-carried state, so matching the fresh stream also proves the log is
    // a sufficient and faithful record of the guidance input.
    //
    // The tear: the depth store is written BEFORE `campaign-state.json`, so a crash
    // between the two leaves the novelty log one generation ahead of the cursor, and
    // a guided resume re-derives that generation from a log that already contains
    // its own entry. Truncating the log below the generation being derived is what
    // keeps the re-derivation identical. The torn generation has to be novel (its
    // own entry is in the log) and exploited (it consults the ancestor set), or the
    // truncation is a no-op and the leg proves nothing. Generation 5 of seed base 3
    // qualifies, which the first segment checks; derivation for generation g
    // depends only on generations below it. A fixture change that moves it fails
    // those checks; a probe of a few seed bases with long campaigns finds the next
    // qualifying pair.
    #[test]
    fn campaign_guided_steers_reproducibly_across_a_tear_and_differs_from_unguided() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("depth.wasm");
        fs::write(&module, wat::parse_str(WASI_DEPTH_MODULE).unwrap()).unwrap();
        let module_path = module.to_str().unwrap().to_string();
        let run = |owned: Vec<String>| {
            let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), directory.path(), &refs)
        };
        let (gens, torn) = (12, 5);
        let campaign_of = |out: &Path, guided: bool, gens: u64| {
            let mut args = vec![
                "campaign".to_string(),
                module_path.clone(),
                "--gens".to_string(),
                gens.to_string(),
                "--plateau-after".to_string(),
                "4".to_string(),
                "--seed-start".to_string(),
                "3".to_string(),
                "--progress-every".to_string(),
                "1".to_string(),
                "--out-dir".to_string(),
                out.to_str().unwrap().to_string(),
            ];
            if guided {
                args.push("--guided".to_string());
            }
            args
        };
        let campaign = |out: &Path, guided: bool| campaign_of(out, guided, gens);
        let succeeded = |label: &str, output: &Output| {
            assert!(
                output.status.success(),
                "{label} campaign failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            campaign_gen_lines(&String::from_utf8_lossy(&output.stdout))
        };

        let first_out = directory.path().join("guided-1");
        let first = run(campaign(&first_out, true));
        let guided_stream = succeeded("guided-1", &first);
        let first_stdout = String::from_utf8_lossy(&first.stdout).into_owned();

        // The first segment ends on the torn generation.
        let split_out = directory.path().join("guided-split");
        let segment = succeeded(
            "guided-split fresh",
            &run(campaign_of(&split_out, true, torn + 1)),
        );
        let segment_lines: Vec<&str> = segment.lines().collect();
        assert_eq!(segment_lines.len() as u64, torn + 1);
        let novel = campaign_depth_meta(&split_out)["new_depth_log"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry[0].as_u64() == Some(torn));
        assert!(novel, "the torn generation must be novel");
        assert!(
            segment_lines[torn as usize].contains(" guided=exploit:"),
            "the torn generation must consult the ancestor set: {}",
            segment_lines[torn as usize]
        );

        // Stage the tear: the cursor rewinds by one, the depth store keeps its
        // entry for the generation about to be re-run.
        let state_path = split_out.join("campaign-state.json");
        let mut state: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        state["generations_done"] = serde_json::Value::from(torn);
        let classes = state["classes"].as_object_mut().unwrap();
        let ok = classes.get_mut("OK").expect("a clean campaign records OK");
        *ok = serde_json::Value::from(ok.as_u64().unwrap() - 1);
        fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
        let resumed = succeeded(
            "guided-split resumed",
            &run(vec![
                "campaign".to_string(),
                "--resume".to_string(),
                "--progress-every".to_string(),
                "1".to_string(),
                "--out-dir".to_string(),
                split_out.to_str().unwrap().to_string(),
            ]),
        );
        assert_eq!(
            resumed, segment_lines[torn as usize],
            "the re-run generation must be derived exactly as the original run derived it"
        );

        let extended = succeeded(
            "guided-split extended",
            &run(vec![
                "campaign".to_string(),
                "--extend".to_string(),
                (gens - torn - 1).to_string(),
                "--out-dir".to_string(),
                split_out.to_str().unwrap().to_string(),
                "--progress-every".to_string(),
                "1".to_string(),
            ]),
        );
        assert_eq!(
            guided_stream,
            [segment, extended].join("\n"),
            "a fresh guided campaign and one extended from its first generations must \
             derive identical generations at one seed base"
        );

        let plain_stream = succeeded(
            "unguided",
            &run(campaign(&directory.path().join("unguided"), false)),
        );
        // A guided line carries its decision as a trailing ` guided=…` field, which an
        // unguided line does not have. Strip it before comparing the two modes, so
        // the comparison is about the DERIVATION (seed + class) and cannot pass just
        // because the annotation itself differs.
        let derivation_only = |stream: &str| {
            stream
                .lines()
                .map(|line| line.split(" guided=").next().unwrap_or(line).to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };

        // `--guided` is part of the recorded spec, so re-supplying it on the
        // continuation is refused rather than silently ignored — the out-dir's spec
        // is what actually decides the derivation.
        let toggled = run(vec![
            "campaign".to_string(),
            "--extend".to_string(),
            "2".to_string(),
            "--guided".to_string(),
            "--out-dir".to_string(),
            split_out.to_str().unwrap().to_string(),
        ]);
        assert_eq!(toggled.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&toggled.stderr)
                .contains("--guided cannot be used with --extend/--resume"),
            "toggling guidance on a continuation must be refused:\n{}",
            String::from_utf8_lossy(&toggled.stderr)
        );
        assert_ne!(
            derivation_only(&guided_stream),
            derivation_only(&plain_stream),
            "guided derivation that matches the unguided stream is an inert knob"
        );
        // Generation 0 has nothing to steer toward, so it must be IDENTICAL — the
        // honest fallback, not an arbitrary reseeding.
        assert_eq!(
            derivation_only(&guided_stream).lines().next(),
            derivation_only(&plain_stream).lines().next(),
            "the first generation has no ancestors and must match the unguided one"
        );
        assert!(
            guided_stream
                .lines()
                .next()
                .unwrap()
                .ends_with(" guided=none"),
            "the first generation must report that it had nothing to steer toward"
        );

        // Non-vacuity is reported, not merely implied.
        assert!(
            first_stdout.contains("-- guided generation scheduling --"),
            "a guided campaign must report what it steered:\n{first_stdout}"
        );
        assert!(
            !first_stdout.contains("PATINA_CAMPAIGN_GUIDED_VACUOUS"),
            "this campaign has real novelty, so guidance must not be vacuous:\n{first_stdout}"
        );
        let exploited = first_stdout
            .lines()
            .find(|line| line.starts_with("generations=") && line.contains("exploited="))
            .and_then(|line| {
                line.split_whitespace()
                    .find_map(|token| token.strip_prefix("exploited="))
            })
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        assert!(
            exploited > 0,
            "guidance reported zero exploited generations:\n{first_stdout}"
        );
        assert!(
            first_stdout.contains(&format!("guided_exploit={exploited}")),
            "PATINA_CAMPAIGN_COMPLETE must carry the guidance tally:\n{first_stdout}"
        );

        let json_out = directory.path().join("json");
        let mut json_args = campaign(&json_out, true);
        json_args.extend(["--format".to_string(), "json".to_string()]);
        let envelope = campaign_json_stdout(&run(json_args));
        assert_eq!(envelope["guidance"]["state"], "active");
        assert_eq!(envelope["guidance"]["exploited"], exploited);
        assert_eq!(
            envelope["guidance"]["generations"].as_u64().unwrap(),
            envelope["guidance"]["exploited"].as_u64().unwrap()
                + envelope["guidance"]["explored"].as_u64().unwrap()
                + envelope["guidance"]["no_ancestors"].as_u64().unwrap(),
            "the guidance tally must account for every generation"
        );
    }

    // A guest with NO seed-dependent behaviour: identical fuel and identical hostcall
    // kinds every generation, so only the bootstrap generation is ever novel. With the
    // bootstrap excluded from the ancestor pool that leaves nothing to steer toward,
    // which must surface as an unguided-identical stream AND a loud vacuity line —
    // never as steering that quietly resamples the baseline.
    const WASI_CONSTANT_MODULE: &str = r#"(module
    (import "wasi_snapshot_preview1" "fd_write"
        (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 64) "constant\n")
    (func (export "_start")
        (i32.store (i32.const 0) (i32.const 64))
        (i32.store (i32.const 4) (i32.const 9))
        (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 16)))))"#;

    #[test]
    fn campaign_guided_reports_vacuous_when_only_the_bootstrap_was_novel() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("constant.wasm");
        fs::write(&module, wat::parse_str(WASI_CONSTANT_MODULE).unwrap()).unwrap();
        let module_path = module.to_str().unwrap().to_string();
        let run = |owned: Vec<String>| {
            let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), directory.path(), &refs)
        };
        // A pool that ever filled would steer from generation 1 on, so a few
        // generations past the bootstrap show it never did.
        let gens = 4;
        let args = |out: &Path, guided: bool| {
            let mut args = vec![
                "campaign".to_string(),
                module_path.clone(),
                "--gens".to_string(),
                gens.to_string(),
                "--progress-every".to_string(),
                "1".to_string(),
                "--out-dir".to_string(),
                out.to_str().unwrap().to_string(),
            ];
            if guided {
                args.push("--guided".to_string());
            }
            args
        };

        let guided_out = directory.path().join("guided");
        let plain_out = directory.path().join("plain");
        let guided = run(args(&guided_out, true));
        let plain = run(args(&plain_out, false));
        assert!(guided.status.success() && plain.status.success());
        let guided_stdout = String::from_utf8_lossy(&guided.stdout).into_owned();

        // Only the bootstrap was novel, so the pool is empty and every generation
        // reports that it had nothing to steer toward.
        let novelty = campaign_depth_meta(&guided_out)["new_depth_log"]
            .as_array()
            .unwrap()
            .len();
        assert_eq!(
            novelty, 1,
            "this fixture must produce exactly one (bootstrap) novelty entry"
        );
        assert!(
            guided_stdout.contains("PATINA_CAMPAIGN_GUIDED_VACUOUS"),
            "a guided campaign that never steered must say so:\n{guided_stdout}"
        );
        assert_eq!(
            campaign_gen_lines(&guided_stdout)
                .lines()
                .filter(|line| line.contains(" guided=none"))
                .count(),
            gens,
            "every generation had no ancestor to steer toward"
        );

        // And the derivation is byte-identical to the unguided sweep: an empty pool
        // degrades to the default scheme rather than to something arbitrary.
        let strip = |stream: String| {
            stream
                .lines()
                .map(|line| line.split(" guided=").next().unwrap_or(line).to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(
            strip(campaign_gen_lines(&guided_stdout)),
            strip(campaign_gen_lines(&String::from_utf8_lossy(&plain.stdout))),
            "with nothing to steer toward, guided must reproduce the unguided stream"
        );

        let json_out = directory.path().join("json");
        let mut json_args = args(&json_out, true);
        json_args.extend(["--format".to_string(), "json".to_string()]);
        let envelope = campaign_json_stdout(&run(json_args));
        assert_eq!(envelope["guidance"]["state"], "vacuous");
        assert_eq!(envelope["guidance"]["exploited"], 0);
    }
}
