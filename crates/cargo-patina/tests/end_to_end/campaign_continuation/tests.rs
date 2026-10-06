//! Campaign extension, interruption recovery, and continuation refusals.

use super::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_timeout_does_not_save_incomplete_trace() {
    let workspace = native_workspace();
    let directory = tempdir().unwrap();
    let source = directory.path().join("spin_forever.rs");
    fs::write(
        &source,
        r#"fn main() {
    loop {
        std::hint::spin_loop();
    }
}
"#,
    )
    .unwrap();
    let guest = directory.path().join("spin-forever");
    invoke(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            guest.to_str().unwrap(),
        ],
    );

    let out = directory.path().join("timeout-campaign");
    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "campaign",
            guest.to_str().unwrap(),
            "--gens",
            "1",
            "--timeout-secs",
            "1",
            "--progress-every",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
        ],
    );
    assert_eq!(
        ran.status.code(),
        Some(1),
        "timeout campaign should report the INFRA failure\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    let stdout = String::from_utf8_lossy(&ran.stdout);
    assert!(
        stdout.contains("class=INFRA"),
        "timeout was not classified as INFRA:\n{stdout}"
    );
    assert!(
        stdout.contains("PATINA_CAMPAIGN_GEN generation=0"),
        "missing per-generation timeout line:\n{stdout}"
    );

    let scratch = out.join("traces/generation-0.patina");
    assert!(
        !scratch.exists(),
        "timed-out generation must not leave a zero-byte scratch trace"
    );
    let traces_dir = out.join("traces");
    let leftovers = fs::read_dir(&traces_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        leftovers.is_empty(),
        "timed-out generation left trace scratch files: {leftovers:?}"
    );
    assert!(
        !out.join("failures/generation-0.patina").exists(),
        "campaign must not save an incomplete failure trace"
    );
    let store: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("signatures.json")).unwrap()).unwrap();
    let signature = &store["signatures"].as_array().unwrap()[0];
    assert_eq!(signature["class"], "INFRA");
    assert!(
        signature.get("trace").is_none(),
        "timeout signature should fall back to a rerun command, not an unreplayable trace: {signature:#}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_extend_equals_fresh_campaign() {
    let workspace = native_workspace();
    let directory = tempdir().unwrap();
    let guest = directory.path().join("liveness-guest");

    build_liveness_guest(&guest);

    let campaign_args = |out: &Path, gens: u64, json: bool| {
        let mut args = vec![
            "campaign".to_string(),
            guest.to_str().unwrap().to_string(),
            "--gens".to_string(),
            gens.to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
            "--buggify".to_string(),
            "--liveness-watchdog".to_string(),
            "600000000000".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ];
        if json {
            args.extend(["--format".to_string(), "json".to_string()]);
        }
        args
    };
    let run = |owned: Vec<String>| {
        let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
        invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &refs)
    };
    let concat_gen_lines = |outputs: &[&str]| {
        outputs
            .iter()
            .map(|text| campaign_gen_lines(text))
            .filter(|lines| !lines.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    };

    let out = directory.path().join("camp");
    let fresh = run(campaign_args(&out, 12, false));
    assert_eq!(
        fresh.status.code(),
        Some(1),
        "fresh campaign should find the planted failure\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stdout),
        String::from_utf8_lossy(&fresh.stderr)
    );
    let fresh_stdout = String::from_utf8_lossy(&fresh.stdout).into_owned();
    let fresh_signatures = fs::read_to_string(out.join("signatures.json")).unwrap();
    let fresh_sites = fs::read_to_string(out.join("sites.json")).unwrap();
    let fresh_state = campaign_state_without_invocations(&out.join("campaign-state.json"));

    fs::remove_dir_all(&out).unwrap();
    let split1 = run(campaign_args(&out, 5, false));
    assert!(
        matches!(split1.status.code(), Some(0) | Some(1)),
        "split segment exited unexpectedly: {}\nstdout:\n{}\nstderr:\n{}",
        split1.status,
        String::from_utf8_lossy(&split1.stdout),
        String::from_utf8_lossy(&split1.stderr)
    );
    let extend_args = vec![
        "campaign".to_string(),
        "--extend".to_string(),
        "7".to_string(),
        "--out-dir".to_string(),
        out.to_str().unwrap().to_string(),
        "--progress-every".to_string(),
        "1".to_string(),
    ];
    let split2 = run(extend_args);
    assert_eq!(
        split2.status.code(),
        Some(1),
        "extended campaign should preserve cumulative failure exit\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&split2.stdout),
        String::from_utf8_lossy(&split2.stderr)
    );
    let split1_stdout = String::from_utf8_lossy(&split1.stdout);
    let split2_stdout = String::from_utf8_lossy(&split2.stdout);
    assert!(
        split2_stdout.contains("PATINA_CAMPAIGN_RESUME")
            && split2_stdout.contains("done=5")
            && split2_stdout.contains("target=12"),
        "extension should announce the recorded cursor and cumulative target:\n{split2_stdout}"
    );
    assert!(
        split2_stdout.contains("PATINA_CAMPAIGN_COMPLETE generations=12"),
        "extension summary must be cumulative:\n{split2_stdout}"
    );
    assert_eq!(
        campaign_gen_lines(&fresh_stdout),
        concat_gen_lines(&[&split1_stdout, &split2_stdout]),
        "k-then-extend must reproduce the fresh per-generation stream"
    );
    assert_eq!(
        split1_stdout.matches("NOVEL").count() + split2_stdout.matches("NOVEL").count(),
        1,
        "novelty must survive the split"
    );
    assert_eq!(
        fresh_signatures,
        fs::read_to_string(out.join("signatures.json")).unwrap(),
        "k-then-extend must reproduce the fresh signature store"
    );
    assert_eq!(
        fresh_sites,
        fs::read_to_string(out.join("sites.json")).unwrap(),
        "k-then-extend must reproduce the fresh sites.json store"
    );
    assert_eq!(
        fresh_state,
        campaign_state_without_invocations(&out.join("campaign-state.json")),
        "k-then-extend must reproduce persisted state except audit invocations"
    );

    let json_out = directory.path().join("camp-json");
    let fresh_json = run(campaign_args(&json_out, 12, true));
    assert_eq!(fresh_json.status.code(), Some(1));
    let fresh_envelope = campaign_json_stdout(&fresh_json);
    fs::remove_dir_all(&json_out).unwrap();
    let split_json1 = run(campaign_args(&json_out, 5, true));
    assert!(matches!(split_json1.status.code(), Some(0) | Some(1)));
    let split_json2 = run(vec![
        "campaign".to_string(),
        "--extend".to_string(),
        "7".to_string(),
        "--out-dir".to_string(),
        json_out.to_str().unwrap().to_string(),
        "--format".to_string(),
        "json".to_string(),
    ]);
    assert_eq!(split_json2.status.code(), Some(1));
    let split_envelope = campaign_json_stdout(&split_json2);
    assert_eq!(
        campaign_json_without_invocations(&fresh_envelope),
        campaign_json_without_invocations(&split_envelope),
        "k-then-extend final JSON envelope must match fresh except audit invocations"
    );
    assert_eq!(split_envelope["invocations"].as_array().unwrap().len(), 2);
    assert!(
        split_envelope["artifacts"]["campaign_state"]
            .as_str()
            .unwrap()
            .ends_with("campaign-state.json")
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_extend_reproduces_aux_store_bytes_for_sites_and_coverage() {
    let workspace = native_workspace();
    let directory = tempdir().unwrap();
    let source = directory.path().join("aux_guest.rs");
    let guest = directory.path().join("aux-guest");
    fs::write(
        &source,
        r#"fn main() {
    eprintln!("PATINA_SDK_REPORT enabled=1 site=aux|sometimes|a1|e3|f1|r1|s1|v0|k-|@src/main.rs:1");
    let mut sum = 0u64;
    for i in 0..128u64 {
        sum = sum.wrapping_add(i.rotate_left((i % 17) as u32));
        std::hint::black_box(sum);
    }
    println!("AUX_DONE {sum}");
}
"#,
    )
    .unwrap();
    let built = invoke(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            guest.to_str().unwrap(),
            "--yield-points",
        ],
    );
    assert!(
        built.status.success(),
        "building aux coverage guest failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );

    let campaign_args = |out: &Path, gens: u64| {
        vec![
            "campaign".to_string(),
            guest.to_str().unwrap().to_string(),
            "--gens".to_string(),
            gens.to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ]
    };
    let run = |owned: Vec<String>| {
        let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
        invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &refs)
    };
    let concat_gen_lines = |outputs: &[&str]| {
        outputs
            .iter()
            .map(|text| campaign_gen_lines(text))
            .filter(|lines| !lines.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    };

    let fresh_out = directory.path().join("fresh");
    let fresh = run(campaign_args(&fresh_out, 6));
    assert!(
        fresh.status.success(),
        "fresh aux campaign failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stdout),
        String::from_utf8_lossy(&fresh.stderr)
    );
    let fresh_stdout = String::from_utf8_lossy(&fresh.stdout).into_owned();
    let fresh_sites = fs::read_to_string(fresh_out.join("sites.json")).unwrap();
    let fresh_site_json: serde_json::Value = serde_json::from_str(&fresh_sites).unwrap();
    assert_eq!(fresh_site_json["generations_observed"], 6);
    assert_eq!(fresh_site_json["sites"][0]["registered_gens"], 6);
    let fresh_coverage_hashes = campaign_coverage_file_hashes(&fresh_out);
    let fresh_state = campaign_state_without_invocations(&fresh_out.join("campaign-state.json"));

    let split_out = directory.path().join("split");
    let split1 = run(campaign_args(&split_out, 2));
    assert!(
        split1.status.success(),
        "first split aux segment failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&split1.stdout),
        String::from_utf8_lossy(&split1.stderr)
    );
    let split2 = run(vec![
        "campaign".to_string(),
        "--extend".to_string(),
        "4".to_string(),
        "--out-dir".to_string(),
        split_out.to_str().unwrap().to_string(),
        "--progress-every".to_string(),
        "1".to_string(),
    ]);
    assert!(
        split2.status.success(),
        "extended aux campaign failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&split2.stdout),
        String::from_utf8_lossy(&split2.stderr)
    );
    let split1_stdout = String::from_utf8_lossy(&split1.stdout);
    let split2_stdout = String::from_utf8_lossy(&split2.stdout);
    assert_eq!(
        campaign_gen_lines(&fresh_stdout),
        concat_gen_lines(&[&split1_stdout, &split2_stdout]),
        "aux k-then-extend must reproduce the fresh per-generation stream"
    );
    assert_eq!(
        fresh_sites,
        fs::read_to_string(split_out.join("sites.json")).unwrap(),
        "aux k-then-extend must reproduce sites.json bytes"
    );
    assert_eq!(
        fresh_coverage_hashes,
        campaign_coverage_file_hashes(&split_out),
        "aux k-then-extend must reproduce coverage store file hashes"
    );
    println!(
        "AUX_STORE_BYTE_EQUALITY sites.json_bytes={} coverage_hashes={fresh_coverage_hashes:?}",
        fresh_sites.len()
    );
    assert_eq!(
        fresh_state,
        campaign_state_without_invocations(&split_out.join("campaign-state.json")),
        "aux k-then-extend must reproduce persisted state except audit invocations"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_resume_after_interruption_matches_fresh_campaign() {
    let workspace = native_workspace();
    let directory = tempdir().unwrap();
    let source = directory.path().join("burn.rs");
    let guest = directory.path().join("burn-guest");
    fs::write(
        &source,
        r#"
fn main() {
    let mut x = 0u64;
    for i in 0..20_000_000u64 {
        x = x.wrapping_add(i.rotate_left((i % 31) as u32));
        std::hint::black_box(x);
    }
    println!("BURN_DONE {x}");
}
"#,
    )
    .unwrap();
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
        "building burn guest failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );

    let campaign_args = |out: &Path| {
        vec![
            "campaign".to_string(),
            guest.to_str().unwrap().to_string(),
            "--gens".to_string(),
            "8".to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ]
    };
    let run = |owned: Vec<String>| {
        let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
        invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &refs)
    };

    let out = directory.path().join("camp");
    let fresh = run(campaign_args(&out));
    assert!(
        fresh.status.success(),
        "fresh burn campaign failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stdout),
        String::from_utf8_lossy(&fresh.stderr)
    );
    let fresh_stdout = String::from_utf8_lossy(&fresh.stdout).into_owned();
    let fresh_state = campaign_state_without_invocations(&out.join("campaign-state.json"));
    let fresh_signatures = fs::read_to_string(out.join("signatures.json")).unwrap();

    fs::remove_dir_all(&out).unwrap();
    let owned = campaign_args(&out);
    let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cargo-patina"))
        .current_dir(workspace)
        .args(&refs)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let state_path = out.join("campaign-state.json");
    let deadline = Instant::now() + Duration::from_secs(120);
    let observed_done = loop {
        if state_path.exists() {
            let state: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
            let done = state["generations_done"].as_u64().unwrap();
            if (2..8).contains(&done) {
                break done;
            }
            assert!(done < 8, "campaign finished before it could be interrupted");
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for an interruptible campaign checkpoint"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let concurrent = run(campaign_args(&out));
    assert_eq!(
        concurrent.status.code(),
        Some(2),
        "second writer should fail immediately while the first campaign holds the lock\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&concurrent.stdout),
        String::from_utf8_lossy(&concurrent.stderr)
    );
    assert!(
        String::from_utf8_lossy(&concurrent.stderr)
            .contains("another campaign is writing this out-dir"),
        "concurrent writer refusal should name the lock:\n{}",
        String::from_utf8_lossy(&concurrent.stderr)
    );
    child.kill().unwrap();
    let interrupted = child.wait_with_output().unwrap();
    assert!(
        !interrupted.status.success(),
        "killed campaign unexpectedly exited successfully"
    );
    assert!(
        state_path.exists(),
        "interrupted campaign left no state file"
    );
    assert!(
        out.join("signatures.json").exists(),
        "interrupted campaign left no derived signature store"
    );

    let resumed = run(vec![
        "campaign".to_string(),
        "--resume".to_string(),
        "--out-dir".to_string(),
        out.to_str().unwrap().to_string(),
        "--progress-every".to_string(),
        "1".to_string(),
    ]);
    assert!(
        resumed.status.success(),
        "resume failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&resumed.stdout),
        String::from_utf8_lossy(&resumed.stderr)
    );
    let interrupted_stdout = String::from_utf8_lossy(&interrupted.stdout);
    let resumed_stdout = String::from_utf8_lossy(&resumed.stdout);
    assert!(
        resumed_stdout.contains("PATINA_CAMPAIGN_RESUME")
            && resumed_stdout.contains(&format!("done={observed_done}"))
            && resumed_stdout.contains("target=8"),
        "resume should announce the persisted cursor:\n{resumed_stdout}"
    );
    let combined = [
        campaign_gen_lines(&interrupted_stdout),
        campaign_gen_lines(&resumed_stdout),
    ]
    .into_iter()
    .filter(|lines| !lines.is_empty())
    .collect::<Vec<_>>()
    .join("\n");
    assert_eq!(
        campaign_gen_lines(&fresh_stdout),
        combined,
        "interrupted + resumed stream must match a fresh campaign"
    );
    assert_eq!(
        fresh_state,
        campaign_state_without_invocations(&state_path),
        "interrupted + resumed state must match fresh except audit invocations"
    );
    assert_eq!(
        fresh_signatures,
        fs::read_to_string(out.join("signatures.json")).unwrap(),
        "interrupted + resumed signature store must match fresh"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_continuation_refusals_are_loud() {
    let directory = tempdir().unwrap();
    let cwd = directory.path();
    let module = cwd.join("noop.wasm");
    fs::write(
        &module,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap(),
    )
    .unwrap();
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let run = |args: &[&str]| invoke_unchecked(patina, cwd, args);
    let assert_refuses = |output: Output, needle: &str| {
        assert_eq!(
            output.status.code(),
            Some(2),
            "expected refusal containing {needle:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(needle),
            "refusal did not contain {needle:?}:\n{stderr}"
        );
    };

    let missing = cwd.join("missing-out");
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            missing.to_str().unwrap(),
        ]),
        "no campaign-state.json",
    );

    let pre_steering = cwd.join("pre-steering");
    fs::create_dir_all(&pre_steering).unwrap();
    fs::write(
        pre_steering.join("signatures.json"),
        r#"{"schema":"patina.campaign.signatures/v1","signatures":[]}"#,
    )
    .unwrap();
    assert_refuses(
        run(&[
            "campaign",
            "--resume",
            "--out-dir",
            pre_steering.to_str().unwrap(),
        ]),
        "no campaign-state.json",
    );

    let out = cwd.join("camp");
    let fresh = run(&[
        "campaign",
        module.to_str().unwrap(),
        "--gens",
        "1",
        "--out-dir",
        out.to_str().unwrap(),
    ]);
    assert!(
        fresh.status.success(),
        "fresh campaign failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stdout),
        String::from_utf8_lossy(&fresh.stderr)
    );
    assert_refuses(
        run(&[
            "campaign",
            module.to_str().unwrap(),
            "--gens",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
        ]),
        "already contains campaign-state.json",
    );
    assert_refuses(
        run(&["campaign", "--resume", "--out-dir", out.to_str().unwrap()]),
        "campaign complete at 1/1",
    );
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
            "--gens",
            "2",
        ]),
        "out-dir's recorded spec is authoritative",
    );
    assert_refuses(
        run(&[
            "campaign",
            module.to_str().unwrap(),
            "--extend",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
        ]),
        "artifact positional cannot be used with --extend/--resume",
    );
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--resume",
            "--out-dir",
            out.to_str().unwrap(),
        ]),
        "choose exactly one continuation mode",
    );
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "0",
            "--out-dir",
            out.to_str().unwrap(),
        ]),
        "--extend must be >= 1",
    );

    let heartbeat_out = cwd.join("heartbeat-camp");
    let heartbeat_fresh = run(&[
        "campaign",
        module.to_str().unwrap(),
        "--gens",
        "3",
        "--progress-every",
        "0",
        "--out-dir",
        heartbeat_out.to_str().unwrap(),
    ]);
    assert!(heartbeat_fresh.status.success());
    let heartbeat_extend = run(&[
        "campaign",
        "--extend",
        "2",
        "--out-dir",
        heartbeat_out.to_str().unwrap(),
        "--progress-every",
        "2",
    ]);
    assert!(
        heartbeat_extend.status.success(),
        "heartbeat extension failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&heartbeat_extend.stdout),
        String::from_utf8_lossy(&heartbeat_extend.stderr)
    );
    let heartbeat_stdout = String::from_utf8_lossy(&heartbeat_extend.stdout);
    assert!(
        heartbeat_stdout.contains("PATINA_CAMPAIGN_RESUME")
            && heartbeat_stdout.contains("done=3")
            && heartbeat_stdout.contains("target=5"),
        "resume line should be cumulative:\n{heartbeat_stdout}"
    );
    assert!(
        heartbeat_stdout.contains("PATINA_CAMPAIGN_PROGRESS generation=4/5")
            && heartbeat_stdout.contains("failures=0")
            && heartbeat_stdout.contains("OK=4"),
        "extension heartbeat should be cumulative:\n{heartbeat_stdout}"
    );
    assert!(
        heartbeat_stdout.contains("PATINA_CAMPAIGN_COMPLETE generations=5"),
        "extension summary should be cumulative:\n{heartbeat_stdout}"
    );

    let schema_out = cwd.join("schema-camp");
    let schema_fresh = run(&[
        "campaign",
        module.to_str().unwrap(),
        "--gens",
        "1",
        "--out-dir",
        schema_out.to_str().unwrap(),
    ]);
    assert!(schema_fresh.status.success());
    let schema_path = schema_out.join("campaign-state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&schema_path).unwrap()).unwrap();
    state["schema"] = "patina.campaign.state/v999".into();
    fs::write(&schema_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            schema_out.to_str().unwrap(),
        ]),
        "different cargo-patina version",
    );

    let corrupt_out = cwd.join("corrupt-camp");
    let corrupt_fresh = run(&[
        "campaign",
        module.to_str().unwrap(),
        "--gens",
        "1",
        "--out-dir",
        corrupt_out.to_str().unwrap(),
    ]);
    assert!(corrupt_fresh.status.success());
    let corrupt_path = corrupt_out.join("campaign-state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&corrupt_path).unwrap()).unwrap();
    state["classes"] = serde_json::json!({"MYSTERY": 1});
    fs::write(&corrupt_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            corrupt_out.to_str().unwrap(),
        ]),
        "corrupt",
    );

    let missing_artifact_module = cwd.join("missing-artifact.wasm");
    fs::write(
        &missing_artifact_module,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap(),
    )
    .unwrap();
    let missing_artifact_out = cwd.join("missing-artifact-camp");
    let missing_artifact_fresh = run(&[
        "campaign",
        missing_artifact_module.to_str().unwrap(),
        "--gens",
        "1",
        "--out-dir",
        missing_artifact_out.to_str().unwrap(),
    ]);
    assert!(missing_artifact_fresh.status.success());
    fs::remove_file(&missing_artifact_module).unwrap();
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            missing_artifact_out.to_str().unwrap(),
        ]),
        "cannot be read",
    );

    let hash_module = cwd.join("hash.wasm");
    fs::write(
        &hash_module,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap(),
    )
    .unwrap();
    let hash_out = cwd.join("hash-camp");
    let hash_fresh = run(&[
        "campaign",
        hash_module.to_str().unwrap(),
        "--gens",
        "1",
        "--out-dir",
        hash_out.to_str().unwrap(),
    ]);
    assert!(hash_fresh.status.success());
    fs::write(
        &hash_module,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start") (nop)))"#)
            .unwrap(),
    )
    .unwrap();
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            hash_out.to_str().unwrap(),
        ]),
        "the artifact changed since this campaign started",
    );
}

// The campaign classifier `--selftest` proves every outcome class is reachable
// and the signature store dedups/novelty logic bites — the campaign peer of
// fuzz-sweep's `--selftest`.
#[test]
fn campaign_selftest_passes() {
    let ran = invoke(native_workspace(), &["campaign", "--selftest"]);
    assert!(
        ran.status.success(),
        "campaign --selftest failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("CAMPAIGN SELFTEST PASSED"),
        "missing pass marker:\n{}",
        String::from_utf8_lossy(&ran.stdout)
    );
}
