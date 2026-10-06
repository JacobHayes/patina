//! Campaign depth checkpoint extension and torn-checkpoint recovery.

#[cfg(test)]
mod tests {
    use super::super::*;

    // The depth store follows the shared aux-store resume contract: k generations
    // then `--extend` must reproduce the fresh campaign's persisted bytes exactly.
    // The hostcall sums are saturating ADDS, so a missing watermark skip would
    // double-count them and this comparison would fail — the WASI mirror of the
    // native coverage store's idempotency proof.
    #[test]
    fn campaign_extend_reproduces_aux_store_bytes_for_wasi_depth() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("depth.wasm");
        fs::write(&module, wat::parse_str(WASI_DEPTH_MODULE).unwrap()).unwrap();
        let module_path = module.to_str().unwrap().to_string();
        let run = |owned: Vec<String>| {
            let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), directory.path(), &refs)
        };
        let campaign_args = |out: &Path, gens: u64| {
            vec![
                "campaign".to_string(),
                module_path.clone(),
                "--gens".to_string(),
                gens.to_string(),
                "--plateau-after".to_string(),
                "4".to_string(),
                "--progress-every".to_string(),
                "1".to_string(),
                "--out-dir".to_string(),
                out.to_str().unwrap().to_string(),
            ]
        };

        let fresh_out = directory.path().join("fresh");
        let fresh = run(campaign_args(&fresh_out, 12));
        assert!(
            fresh.status.success(),
            "fresh WASI depth campaign failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&fresh.stdout),
            String::from_utf8_lossy(&fresh.stderr)
        );
        let fresh_stdout = String::from_utf8_lossy(&fresh.stdout).into_owned();
        let fresh_meta_bytes =
            fs::read_to_string(fresh_out.join("depth").join("meta.json")).unwrap();
        let meta = campaign_depth_meta(&fresh_out);

        // Non-vacuity: every generation ran to completion, so every generation must
        // have contributed a measurement. `generations_with_depth=0` would be a store
        // that cannot tell "no data" from "zero depth".
        assert_eq!(meta["generations_applied"], 12);
        assert_eq!(meta["generations_with_depth"], 12);
        assert_eq!(meta["hostcall_kinds"], 3);
        assert_eq!(meta["hostcalls"]["fd_write"], 12);
        assert!(meta["fuel_max"].as_u64().unwrap() > 0);
        assert!(meta["fuel_total"].as_u64().unwrap() >= meta["fuel_max"].as_u64().unwrap());
        assert!(
            !meta["new_depth_log"].as_array().unwrap().is_empty(),
            "the first generation always establishes a fuel high-water mark"
        );

        // The plateau flag is exactly the arc's rule over the persisted log, not an
        // approximation of it.
        let last_new = meta["last_new_depth_gen"].as_u64().unwrap();
        let expected_plateau = 11 - last_new >= 4;
        assert_eq!(
            meta["depth_plateaued"].as_bool().unwrap(),
            expected_plateau,
            "depth_plateaued must be (generations_applied - 1 - last_new_depth_gen) >= plateau_after"
        );
        assert!(
            fresh_stdout.contains(&format!("depth_plateaued={}", u8::from(expected_plateau))),
            "PATINA_CAMPAIGN_COMPLETE must carry the depth plateau verdict:\n{fresh_stdout}"
        );
        assert!(
            !fresh_stdout.contains("PATINA_CAMPAIGN_DEPTH_VACUOUS"),
            "a campaign whose generations all reported depth is not vacuous:\n{fresh_stdout}"
        );

        let split_out = directory.path().join("split");
        let split1 = run(campaign_args(&split_out, 4));
        assert!(split1.status.success(), "first WASI depth segment failed");
        let split2 = run(vec![
            "campaign".to_string(),
            "--extend".to_string(),
            "8".to_string(),
            "--out-dir".to_string(),
            split_out.to_str().unwrap().to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
        ]);
        assert!(
            split2.status.success(),
            "extended WASI depth campaign failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&split2.stdout),
            String::from_utf8_lossy(&split2.stderr)
        );
        let split1_stdout = String::from_utf8_lossy(&split1.stdout);
        let split2_stdout = String::from_utf8_lossy(&split2.stdout);
        assert_eq!(
            campaign_gen_lines(&fresh_stdout),
            [
                campaign_gen_lines(&split1_stdout),
                campaign_gen_lines(&split2_stdout)
            ]
            .join("\n"),
            "4-then-extend must reproduce the fresh per-generation stream"
        );
        assert_eq!(
            fresh_meta_bytes,
            fs::read_to_string(split_out.join("depth").join("meta.json")).unwrap(),
            "4-then-extend must reproduce the depth store bytes"
        );
        println!(
            "WASI_DEPTH_STORE_BYTE_EQUALITY bytes={} fuel_max={} kinds={}",
            fresh_meta_bytes.len(),
            meta["fuel_max"],
            meta["hostcall_kinds"]
        );

        // The envelope reports the same accumulation, under its own `depth` object
        // (never folded into `coverage`, which stays honestly unavailable here).
        let json_out = directory.path().join("json");
        let mut json_args = campaign_args(&json_out, 3);
        json_args.extend(["--format".to_string(), "json".to_string()]);
        let json = run(json_args);
        assert!(
            json.status.success(),
            "JSON WASI depth campaign failed:\nstderr:\n{}",
            String::from_utf8_lossy(&json.stderr)
        );
        let envelope = campaign_json_stdout(&json);
        assert_eq!(envelope["depth"]["state"], "available");
        assert_eq!(envelope["depth"]["generations_with_depth"], 3);
        assert_eq!(envelope["coverage"]["edge"]["state"], "unavailable");
        assert_eq!(envelope["coverage"]["edge"]["reason"], "not-native");
        assert!(envelope["artifacts"]["depth_dir"].is_string());
    }

    // The checkpoint-tear leg of the aux-store contract, deterministically staged:
    // the depth store is written BEFORE `campaign-state.json`, so a crash between the
    // two leaves the store one generation ahead of the cursor and resume re-runs that
    // generation. Rewinding the cursor by one reproduces exactly that state without
    // racing a process. The re-run's fold must be skipped by the watermark: the
    // hostcall sums are saturating adds, so folding it twice would inflate them and
    // break the byte comparison below (RED-proven by disabling the skip).
    #[test]
    fn campaign_resume_after_a_depth_checkpoint_tear_does_not_double_fold() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("depth.wasm");
        fs::write(&module, wat::parse_str(WASI_DEPTH_MODULE).unwrap()).unwrap();
        let out = directory.path().join("camp");
        let run = |owned: Vec<String>| {
            let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), directory.path(), &refs)
        };

        let fresh = run(vec![
            "campaign".to_string(),
            module.to_str().unwrap().to_string(),
            "--gens".to_string(),
            "6".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ]);
        assert!(
            fresh.status.success(),
            "fresh depth campaign failed:\nstderr:\n{}",
            String::from_utf8_lossy(&fresh.stderr)
        );
        let untorn_meta = fs::read_to_string(out.join("depth").join("meta.json")).unwrap();
        let torn_hostcalls = campaign_depth_meta(&out)["hostcalls"].clone();

        // Stage the tear: the cursor claims five generations, the depth store already
        // reflects six.
        let state_path = out.join("campaign-state.json");
        let mut state: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        state["generations_done"] = serde_json::Value::from(5u64);
        // The class histogram is validated against the cursor, so it rewinds too —
        // this is a checkpoint tear, not a corrupt out-dir.
        let classes = state["classes"].as_object_mut().unwrap();
        let ok = classes.get_mut("OK").expect("a clean campaign records OK");
        *ok = serde_json::Value::from(ok.as_u64().unwrap() - 1);
        fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

        let resumed = run(vec![
            "campaign".to_string(),
            "--resume".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ]);
        assert!(
            resumed.status.success(),
            "resume after a depth checkpoint tear failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&resumed.stdout),
            String::from_utf8_lossy(&resumed.stderr)
        );
        assert_eq!(
            untorn_meta,
            fs::read_to_string(out.join("depth").join("meta.json")).unwrap(),
            "re-running the torn generation must contribute nothing to the depth store"
        );
        assert_eq!(
            torn_hostcalls,
            campaign_depth_meta(&out)["hostcalls"],
            "hostcall sums must not be double-counted across a resume"
        );
    }
}
