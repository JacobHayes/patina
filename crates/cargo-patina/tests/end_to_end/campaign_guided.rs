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
    #[test]
    fn campaign_guided_steers_reproducibly_and_differs_from_unguided() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("depth.wasm");
        fs::write(&module, wat::parse_str(WASI_DEPTH_MODULE).unwrap()).unwrap();
        let module_path = module.to_str().unwrap().to_string();
        let run = |owned: Vec<String>| {
            let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), directory.path(), &refs)
        };
        let campaign = |out: &Path, guided: bool| {
            let mut args = vec![
                "campaign".to_string(),
                module_path.clone(),
                "--gens".to_string(),
                "24".to_string(),
                "--plateau-after".to_string(),
                "8".to_string(),
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

        let first_out = directory.path().join("guided-1");
        let second_out = directory.path().join("guided-2");
        let plain_out = directory.path().join("unguided");
        let first = run(campaign(&first_out, true));
        let second = run(campaign(&second_out, true));
        let plain = run(campaign(&plain_out, false));
        for (label, output) in [
            ("guided-1", &first),
            ("guided-2", &second),
            ("unguided", &plain),
        ] {
            assert!(
                output.status.success(),
                "{label} campaign failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let first_stdout = String::from_utf8_lossy(&first.stdout).into_owned();
        let guided_stream = campaign_gen_lines(&first_stdout);
        let repeat_stream = campaign_gen_lines(&String::from_utf8_lossy(&second.stdout));
        let plain_stream = campaign_gen_lines(&String::from_utf8_lossy(&plain.stdout));
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

        assert_eq!(
            guided_stream, repeat_stream,
            "two fresh guided campaigns at one seed base must derive identical generations"
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

        // An unguided campaign says nothing about guidance at all — "off" is
        // distinct from "on but did nothing".
        let json_out = directory.path().join("json");
        let mut json_args = campaign(&json_out, true);
        json_args.extend(["--format".to_string(), "json".to_string()]);
        let envelope = campaign_json_stdout(&run(json_args));
        assert_eq!(envelope["guidance"]["state"], "active");
        assert!(envelope["guidance"]["exploited"].as_u64().unwrap() > 0);
        assert_eq!(
            envelope["guidance"]["generations"].as_u64().unwrap(),
            envelope["guidance"]["exploited"].as_u64().unwrap()
                + envelope["guidance"]["explored"].as_u64().unwrap()
                + envelope["guidance"]["no_ancestors"].as_u64().unwrap(),
            "the guidance tally must account for every generation"
        );
    }

    // Resume/extend equivalence for the guided derivation. This is stricter than the
    // unguided case: an extended guided campaign re-derives generation k from the
    // PERSISTED novelty log rather than from loop-carried state, so this proves the
    // log is a sufficient and faithful record of the guidance input.
    #[test]
    fn campaign_guided_extend_matches_a_fresh_guided_campaign() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("depth.wasm");
        fs::write(&module, wat::parse_str(WASI_DEPTH_MODULE).unwrap()).unwrap();
        let module_path = module.to_str().unwrap().to_string();
        let run = |owned: Vec<String>| {
            let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), directory.path(), &refs)
        };
        let campaign = |out: &Path, gens: u64| {
            vec![
                "campaign".to_string(),
                module_path.clone(),
                "--gens".to_string(),
                gens.to_string(),
                "--plateau-after".to_string(),
                "8".to_string(),
                "--guided".to_string(),
                "--progress-every".to_string(),
                "1".to_string(),
                "--out-dir".to_string(),
                out.to_str().unwrap().to_string(),
            ]
        };

        let fresh_out = directory.path().join("fresh");
        let fresh = run(campaign(&fresh_out, 18));
        assert!(
            fresh.status.success(),
            "fresh guided campaign failed:\nstderr:\n{}",
            String::from_utf8_lossy(&fresh.stderr)
        );
        let fresh_stream = campaign_gen_lines(&String::from_utf8_lossy(&fresh.stdout));

        let split_out = directory.path().join("split");
        let split1 = run(campaign(&split_out, 6));
        assert!(split1.status.success(), "first guided segment failed");
        let split2 = run(vec![
            "campaign".to_string(),
            "--extend".to_string(),
            "12".to_string(),
            "--out-dir".to_string(),
            split_out.to_str().unwrap().to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
        ]);
        assert!(
            split2.status.success(),
            "extended guided campaign failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&split2.stdout),
            String::from_utf8_lossy(&split2.stderr)
        );
        assert_eq!(
            fresh_stream,
            [
                campaign_gen_lines(&String::from_utf8_lossy(&split1.stdout)),
                campaign_gen_lines(&String::from_utf8_lossy(&split2.stdout)),
            ]
            .join("\n"),
            "6-then-extend-12 must reproduce the fresh guided stream exactly"
        );

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
    }

    // Fail closed, loudly: a campaign asked to steer with no novelty signal is not a
    // campaign with slightly worse selection, it is a different mode than the
    // operator asked for. A plain (non-yield-point) native binary has no edge
    // coverage and is not WASI, so `--guided` must refuse rather than quietly run
    // unguided.
    #[test]
    fn campaign_guided_refuses_without_a_novelty_signal() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let source = directory.path().join("plain.rs");
        let guest = directory.path().join("plain-guest");
        fs::write(&source, "fn main() { println!(\"PLAIN_DONE\"); }\n").unwrap();
        let built = invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                guest.to_str().unwrap(),
            ],
        );
        assert!(
            built.status.success(),
            "building the plain guest failed:\nstderr:\n{}",
            String::from_utf8_lossy(&built.stderr)
        );

        let refused = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "campaign",
                guest.to_str().unwrap(),
                "--gens",
                "3",
                "--guided",
                "--out-dir",
                directory.path().join("out").to_str().unwrap(),
            ],
        );
        assert_ne!(
            refused.status.code(),
            Some(0),
            "--guided without a novelty signal must not succeed quietly"
        );
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("--guided needs a novelty signal") && stderr.contains("--yield-points"),
            "the refusal must name the cause and the fix:\n{stderr}"
        );
    }

    // Guided derivation under the checkpoint tear, end to end. The depth store is
    // written BEFORE `campaign-state.json`, so a crash between the two leaves the
    // novelty log one generation ahead of the cursor — and a guided resume then
    // re-derives that generation from a log that already contains its own entry.
    // Truncating the log below the generation being derived is what keeps the
    // re-derivation identical; without it a resumed guided campaign silently runs a
    // different generation than the one it is supposedly resuming.
    //
    // The torn generation must be one that was NOVEL, or the truncation is a no-op
    // and the test proves nothing — so the campaign length is chosen from a probe
    // run's novelty log rather than fixed.
    #[test]
    fn campaign_guided_resume_after_a_tear_re_derives_the_same_generation() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("depth.wasm");
        fs::write(&module, wat::parse_str(WASI_DEPTH_MODULE).unwrap()).unwrap();
        let module_path = module.to_str().unwrap().to_string();
        let run = |owned: Vec<String>| {
            let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), directory.path(), &refs)
        };
        let campaign = |out: &Path, gens: u64, seed_start: u64| {
            vec![
                "campaign".to_string(),
                module_path.clone(),
                "--gens".to_string(),
                gens.to_string(),
                "--plateau-after".to_string(),
                "4".to_string(),
                "--guided".to_string(),
                "--seed-start".to_string(),
                seed_start.to_string(),
                "--progress-every".to_string(),
                "1".to_string(),
                "--out-dir".to_string(),
                out.to_str().unwrap().to_string(),
            ]
        };
        let exploited_generations = |stdout: &str| -> Vec<u64> {
            campaign_gen_lines(stdout)
                .lines()
                .filter(|line| line.contains(" guided=exploit:"))
                .filter_map(|line| {
                    line.split_whitespace()
                        .find_map(|token| token.strip_prefix("generation="))
                        .and_then(|value| value.parse::<u64>().ok())
                })
                .collect()
        };

        // The torn generation has to satisfy BOTH conditions or the truncation is a
        // no-op and this test would pass with or without it: its own novelty entry
        // must be in the log (novel), and it must actually consult the ancestor set
        // (exploited). Whether any generation qualifies depends on the fixture's
        // rolls, so search seed bases rather than hard-coding one and hoping.
        // Derivation for generation g depends only on generations below it, so a
        // qualifying g found in a long probe behaves identically in a `--gens g+1`
        // campaign.
        let mut chosen: Option<(u64, u64)> = None;
        for seed_start in 0..8 {
            let probe_out = directory.path().join(format!("probe-{seed_start}"));
            let probe = run(campaign(&probe_out, 24, seed_start));
            assert!(
                probe.status.success(),
                "probe campaign failed:\nstderr:\n{}",
                String::from_utf8_lossy(&probe.stderr)
            );
            let novel: Vec<u64> = campaign_depth_meta(&probe_out)["new_depth_log"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry[0].as_u64().unwrap())
                .collect();
            let exploited = exploited_generations(&String::from_utf8_lossy(&probe.stdout));
            if let Some(generation) = novel
                .iter()
                .rfind(|generation| **generation >= 1 && exploited.contains(generation))
            {
                chosen = Some((seed_start, *generation));
                break;
            }
        }
        let (seed_start, torn) =
            chosen.expect("no seed base produced a generation that is both novel and exploited");

        // Run a campaign whose LAST generation is that one, so tearing the cursor by
        // one lands exactly on it.
        let out = directory.path().join("camp");
        let fresh = run(campaign(&out, torn + 1, seed_start));
        assert!(
            fresh.status.success(),
            "fresh guided campaign failed:\nstderr:\n{}",
            String::from_utf8_lossy(&fresh.stderr)
        );
        let fresh_lines: Vec<String> = campaign_gen_lines(&String::from_utf8_lossy(&fresh.stdout))
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(fresh_lines.len() as u64, torn + 1);
        assert!(
            fresh_lines[torn as usize].contains(" guided=exploit:"),
            "the torn generation must consult the ancestor set: {}",
            fresh_lines[torn as usize]
        );

        // Stage the tear: the cursor rewinds by one, the depth store keeps its entry
        // for the generation about to be re-run.
        let state_path = out.join("campaign-state.json");
        let mut state: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        state["generations_done"] = serde_json::Value::from(torn);
        let classes = state["classes"].as_object_mut().unwrap();
        let ok = classes.get_mut("OK").expect("a clean campaign records OK");
        *ok = serde_json::Value::from(ok.as_u64().unwrap() - 1);
        fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

        let resumed = run(vec![
            "campaign".to_string(),
            "--resume".to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ]);
        assert!(
            resumed.status.success(),
            "guided resume after a tear failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&resumed.stdout),
            String::from_utf8_lossy(&resumed.stderr)
        );
        assert_eq!(
            campaign_gen_lines(&String::from_utf8_lossy(&resumed.stdout)),
            fresh_lines[torn as usize],
            "the re-run generation must be derived exactly as the original run derived it"
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
        let args = |out: &Path, guided: bool| {
            let mut args = vec![
                "campaign".to_string(),
                module_path.clone(),
                "--gens".to_string(),
                "12".to_string(),
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
            12,
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
