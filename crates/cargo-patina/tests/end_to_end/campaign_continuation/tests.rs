//! Campaign continuation, interruption recovery, and continuation refusals.

use super::*;

/// A guest that spins forever, built once per run and shared.
fn spin_forever_guest() -> PathBuf {
    super::super::run_facts::shared_guest("spin-forever", |directory| {
        build_facts_guest(
            directory,
            "spin_forever",
            "fn main() {\n    loop {\n        std::hint::spin_loop();\n    }\n}\n",
        )
    })
}

#[test]
fn campaign_timeout_does_not_save_incomplete_trace() {
    let workspace = native_workspace();
    let directory = tempdir().unwrap();
    let guest = spin_forever_guest();

    let out = directory.path().join("timeout-campaign");
    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_patina"),
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
    // A campaign whose only stop is its own backstop found nothing in the
    // guest: exit 2, patina could not finish what was asked.
    assert_eq!(
        ran.status.code(),
        Some(2),
        "timeout campaign should report the timeout\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    let stdout = String::from_utf8_lossy(&ran.stdout);
    assert!(
        stdout.contains("class=timeout"),
        "timeout was not classified as a timeout:\n{stdout}"
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
    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("campaign-state.json")).unwrap())
            .unwrap();
    let signature = &state["signatures"].as_array().unwrap()[0];
    assert_eq!(signature["class"], "timeout");
    assert!(
        signature.get("trace").is_none(),
        "timeout signature should fall back to a rerun command, not an unreplayable trace: {signature:#}"
    );
}

/// A campaign split into a first segment and an artifact-free continuation to
/// a larger `--gens` is the fresh campaign: the per-generation stream, the
/// signatures (novelty included), the sites store, the coverage store's bytes
/// and the persisted state all match, the continuation runs under the recorded
/// spec (here a non-default seed start), and the state records both
/// invocations.
#[test]
fn a_campaign_continued_to_more_generations_equals_the_fresh_campaign() {
    let workspace = native_workspace();
    let directory = tempdir().unwrap();
    let source = directory.path().join("aux_guest");
    let guest = directory.path().join("aux-guest");
    // Reports one SDK site, runs instrumented code for the coverage store, and
    // fails the same way every generation.
    write_sdk_fixture(
        &source,
        r#"fn main() {
    patina_dst::sometimes!(true, "aux");
    let mut sum = 0u64;
    for i in 0..128u64 {
        sum = sum.wrapping_add(i.rotate_left((i % 17) as u32));
        std::hint::black_box(sum);
    }
    println!("AUX_DONE {sum}");
    std::process::exit(3);
}
"#,
    );
    let manifest = source.join("Cargo.toml");
    let mut contents = fs::read_to_string(&manifest).unwrap();
    contents.push_str("\n[workspace]\n");
    fs::write(&manifest, contents).unwrap();
    let target = common::guest_target_dir("sdk-shared-target");
    invoke_in_with_env(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            guest.to_str().unwrap(),
        ],
        &[("CARGO_TARGET_DIR", target.to_str().unwrap())],
    );

    let run = |args: &[&str]| invoke_unchecked(env!("CARGO_BIN_EXE_patina"), workspace, args);
    // The platform's default build, as a run reports it.
    let ran = run(&["run", guest.to_str().unwrap(), "--format", "json"]);
    let ran: serde_json::Value = serde_json::from_slice(&ran.stdout).unwrap();
    let instrumented = ran["build"] == "instrumented";
    let campaign = |out: &Path, gens: u64| {
        run(&[
            "campaign",
            guest.to_str().unwrap(),
            "--gens",
            &gens.to_string(),
            "--seed-start",
            "3",
            "--progress-every",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
        ])
    };
    let failed = |output: &Output, what: &str| {
        assert_eq!(
            output.status.code(),
            Some(1),
            "{what} should report the guest's failure\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    // The fresh campaign and the split one share an out-dir path, which the
    // stores record.
    let (gens, first_segment) = (4, 2);
    let out = directory.path().join("camp");
    let fresh_stdout = failed(&campaign(&out, gens), "the fresh campaign");
    let read_sites = || fs::read_to_string(out.join("sites.json")).unwrap();
    let fresh_sites = read_sites();
    let fresh_site_json: serde_json::Value = serde_json::from_str(&fresh_sites).unwrap();
    assert_eq!(fresh_site_json["generations_observed"], gens);
    assert_eq!(fresh_site_json["sites"][0]["registered_gens"], gens);
    let fresh_coverage = campaign_coverage_file_hashes(&out, instrumented);
    let state_path = out.join("campaign-state.json");
    let fresh_state = campaign_state_without_invocations(&state_path);

    fs::remove_dir_all(&out).unwrap();
    let split1 = failed(&campaign(&out, first_segment), "the first segment");
    let split2 = failed(
        &run(&[
            "campaign",
            "--gens",
            &gens.to_string(),
            "--out-dir",
            out.to_str().unwrap(),
            "--progress-every",
            "1",
        ]),
        "the continuation",
    );
    assert!(
        split2.contains("PATINA_CAMPAIGN_RESUME")
            && split2.contains(&format!("done={first_segment}"))
            && split2.contains(&format!("target={gens}")),
        "the continuation should announce the recorded cursor and cumulative target:\n{split2}"
    );
    assert!(
        split2.contains(&format!("PATINA_CAMPAIGN_COMPLETE generations={gens}")),
        "the continuation's summary must be cumulative:\n{split2}"
    );
    let split_lines = [campaign_gen_lines(&split1), campaign_gen_lines(&split2)].join("\n");
    assert_eq!(
        campaign_gen_lines(&fresh_stdout),
        split_lines,
        "k-then-continue must reproduce the fresh per-generation stream"
    );
    assert_eq!(
        split1.matches("NOVEL").count() + split2.matches("NOVEL").count(),
        1,
        "novelty must survive the split"
    );
    assert_eq!(
        fresh_sites,
        read_sites(),
        "k-then-continue must reproduce the sites store bytes"
    );
    assert_eq!(
        fresh_coverage,
        campaign_coverage_file_hashes(&out, instrumented),
        "k-then-continue must reproduce coverage store file hashes"
    );
    assert_eq!(
        fresh_state,
        campaign_state_without_invocations(&state_path),
        "k-then-continue must reproduce persisted state except audit invocations"
    );
    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state["invocations"].as_array().unwrap().len(), 2);
}

#[test]
fn an_interrupted_campaign_given_again_matches_the_fresh_campaign() {
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
            "6".to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ]
    };
    let run = |owned: Vec<String>| {
        let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
        invoke_unchecked(env!("CARGO_BIN_EXE_patina"), workspace, &refs)
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

    fs::remove_dir_all(&out).unwrap();
    let owned = campaign_args(&out);
    let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
    let mut child = Command::new(env!("CARGO_BIN_EXE_patina"))
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
            if (2..6).contains(&done) {
                break done;
            }
            assert!(done < 6, "campaign finished before it could be interrupted");
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

    let resumed = run(campaign_args(&out));
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
            && resumed_stdout.contains("target=6"),
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
}

/// A campaign command given again for the out-dir it wrote continues that
/// campaign. A finished one runs nothing and ends as it did; a larger `--gens`
/// runs the generations that are missing; a command for another campaign
/// (other settings, or a source that now builds another guest) is refused
/// with the recorded campaign and its guest untouched.
#[test]
fn a_campaign_command_given_again_continues_its_out_dir() {
    let directory = tempdir().unwrap();
    let cwd = directory.path();
    let source = cwd.join("fails.rs");
    fs::write(&source, "fn main() {\n    std::process::exit(3);\n}\n").unwrap();
    let out = cwd.join("camp");
    let campaign = |extra: &[&str]| {
        let mut args = vec!["campaign", "fails.rs", "--out-dir", "camp"];
        args.extend_from_slice(extra);
        invoke_unchecked(env!("CARGO_BIN_EXE_patina"), cwd, &args)
    };
    let state = || -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(out.join("campaign-state.json")).unwrap()).unwrap()
    };
    let done = || {
        (
            state()["generations_done"].clone(),
            state()["classes"].clone(),
        )
    };

    let first = campaign(&["--gens", "2"]);
    assert_eq!(first.status.code(), Some(1), "{first:?}");
    assert_eq!(done(), (2.into(), serde_json::json!({"failure": 2})));

    let again = campaign(&["--gens", "2"]);
    assert_eq!(again.status.code(), Some(1), "{again:?}");
    assert_eq!(done(), (2.into(), serde_json::json!({"failure": 2})));
    // The second build of the source left nothing behind.
    let mut entries: Vec<String> = fs::read_dir(&out)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with('.'))
        .collect();
    entries.sort();
    assert!(entries.is_empty(), "{entries:?}");

    let more = campaign(&["--gens", "3"]);
    assert_eq!(more.status.code(), Some(1), "{more:?}");
    assert_eq!(done(), (3.into(), serde_json::json!({"failure": 3})));

    let recorded = fs::read(out.join("campaign-state.json")).unwrap();
    let guest = fs::read(out.join("guest")).unwrap();
    let other_settings = campaign(&["--gens", "3", "--vary", "buggify"]);
    assert_eq!(other_settings.status.code(), Some(2), "{other_settings:?}");
    fs::write(&source, "fn main() {\n    std::process::exit(4);\n}\n").unwrap();
    let other_guest = campaign(&["--gens", "3"]);
    assert_eq!(other_guest.status.code(), Some(2), "{other_guest:?}");
    assert_eq!(fs::read(out.join("campaign-state.json")).unwrap(), recorded);
    assert_eq!(fs::read(out.join("guest")).unwrap(), guest);
}

/// Every continuation and reduction that cannot honour an out-dir's recorded
/// campaign is refused by name: a missing state, flags that would
/// override the recorded spec, an unknown schema, corrupt state, another
/// `patina` build (the supervisor builds every generation's run, and its
/// package version stays the same across development builds that behave
/// differently, so the campaign names it by its executable's digest), and an
/// artifact that changed or vanished. A continuation that is allowed reports
/// cumulative progress, a finished one reports its recorded result, and a
/// child launched by another build refuses before it runs anything.
#[test]
fn campaign_continuation_refusals_are_loud() {
    let directory = tempdir().unwrap();
    let cwd = directory.path();
    let pristine = build_facts_guest(cwd, "noop-built", "fn main() {}");
    let module = cwd.join("noop");
    fs::copy(&pristine, &module).unwrap();
    let module_arg = module.to_str().unwrap();
    let patina = env!("CARGO_BIN_EXE_patina");
    let run = |args: &[&str]| invoke_unchecked(patina, cwd, args);
    let report = |output: &Output| {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    };
    let assert_refuses = |output: Output, needle: &str| {
        assert_eq!(
            output.status.code(),
            Some(2),
            "expected refusal containing {needle:?}\n{}",
            report(&output)
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
            "--gens",
            "1",
            "--out-dir",
            missing.to_str().unwrap(),
        ]),
        "no campaign-state.json",
    );
    assert!(
        !missing.exists(),
        "a refused continuation created its out-dir"
    );

    let out = cwd.join("camp");
    let out_dir = out.to_str().unwrap();
    let fresh = run(&["campaign", module_arg, "--gens", "1", "--out-dir", out_dir]);
    assert!(fresh.status.success(), "{}", report(&fresh));
    let state_path = out.join("campaign-state.json");
    let read_state = || -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap()
    };
    let own = supervisor_identity();
    assert_eq!(
        read_state()["supervisor_sha256"].as_str(),
        Some(own.as_str()),
        "a campaign records the digest of the patina that ran it"
    );

    // The same out-dir with other settings would be another campaign.
    assert_refuses(
        run(&[
            "campaign",
            module_arg,
            "--gens",
            "1",
            "--vary",
            "buggify",
            "--out-dir",
            out_dir,
        ]),
        "vary",
    );
    // A finished campaign continued as it is runs nothing and reports what it
    // recorded.
    let finished = run(&["campaign", "--out-dir", out_dir]);
    assert!(finished.status.success(), "{}", report(&finished));
    let finished_stdout = String::from_utf8_lossy(&finished.stdout);
    assert!(
        finished_stdout.contains("PATINA_CAMPAIGN_COMPLETE generations=1")
            && !finished_stdout.contains("PATINA_CAMPAIGN_GEN"),
        "{finished_stdout}"
    );
    // Flag combinations a continuation refuses are parse-level, tested in
    // `campaign::parse`.

    // Each edit to the recorded state is refused, then undone.
    let extend: &[&str] = &["campaign", "--gens", "2", "--out-dir", out_dir];
    let minimized = cwd.join("minimized.patina");
    let reduce: &[&str] = &[
        "minimize",
        "--generation",
        "0",
        "--out-dir",
        out_dir,
        "--output",
        minimized.to_str().unwrap(),
    ];
    let another = format!("sha256:{}", "0".repeat(64));
    type Edit<'a> = (
        &'a str,
        &'a dyn Fn(&mut serde_json::Value),
        &'a [&'a [&'a str]],
    );
    let edits: [Edit; 2] = [
        (
            "different patina version",
            &|state| state["schema"] = "patina.campaign.state/v999".into(),
            &[extend],
        ),
        (
            "supervisor",
            &|state| state["supervisor_sha256"] = another.clone().into(),
            &[extend, reduce],
        ),
    ];
    let original = fs::read(&state_path).unwrap();
    for (needle, edit, commands) in edits {
        let mut state = read_state();
        edit(&mut state);
        fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
        for arguments in commands {
            let refused = run(arguments);
            let stderr = String::from_utf8_lossy(&refused.stderr);
            assert!(
                !refused.status.success() && stderr.contains(needle),
                "`{}` must be refused naming {needle:?}\n{}",
                arguments[0],
                report(&refused)
            );
        }
        assert!(!minimized.exists(), "a refused reduction writes nothing");
        fs::write(&state_path, &original).unwrap();
    }

    // The same build continues, and its heartbeat and summary are cumulative.
    let extended = run(&[
        "campaign",
        "--gens",
        "3",
        "--out-dir",
        out_dir,
        "--progress-every",
        "2",
    ]);
    assert!(extended.status.success(), "{}", report(&extended));
    let extended_stdout = String::from_utf8_lossy(&extended.stdout);
    assert!(
        extended_stdout.contains("PATINA_CAMPAIGN_RESUME")
            && extended_stdout.contains("done=1")
            && extended_stdout.contains("target=3"),
        "resume line should be cumulative:\n{extended_stdout}"
    );
    assert!(
        extended_stdout.contains("PATINA_CAMPAIGN_PROGRESS generation=2/3")
            && extended_stdout.contains("failures=0")
            && extended_stdout.contains("ok=2"),
        "extension heartbeat should be cumulative:\n{extended_stdout}"
    );
    assert!(
        extended_stdout.contains("PATINA_CAMPAIGN_COMPLETE generations=3"),
        "extension summary should be cumulative:\n{extended_stdout}"
    );

    OpenOptions::new()
        .append(true)
        .open(&module)
        .unwrap()
        .write_all(b"\0")
        .unwrap();
    assert_refuses(
        run(extend),
        "the artifact changed since this campaign started",
    );
    fs::remove_file(&module).unwrap();
    assert_refuses(run(extend), "cannot be read");

    fs::copy(&pristine, &module).unwrap();
    let run_expecting = |digest: &str| {
        Command::new(patina)
            .current_dir(cwd)
            .args(["run", module_arg])
            .env("PATINA_RT_EXPECTED_SUPERVISOR_SHA256", digest)
            .output()
            .unwrap()
    };
    let same = run_expecting(&own);
    assert!(
        same.status.success(),
        "the same build runs:\n{}",
        report(&same)
    );
    let refused = run_expecting(&another);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success() && stderr.contains("supervisor_mismatch"),
        "another build must refuse, naming the supervisor:\n{stderr}"
    );
}

/// A campaign killed outright (SIGKILL, so nothing of it runs on the way out)
/// takes its in-flight generation with it. The generation runs in its own
/// process group, outside the campaign's, and its guest here would spin
/// forever: with nobody left to enforce the timeout backstop, a surviving
/// group would run on beside the continuation that re-runs the same generation.
#[test]
fn a_killed_campaign_takes_its_generation_with_it() {
    let workspace = native_workspace();
    let directory = tempdir().unwrap();
    let guest = spin_forever_guest();

    let out = directory.path().join("camp");
    let mut campaign = Command::new(env!("CARGO_BIN_EXE_patina"))
        .current_dir(workspace)
        .args([
            "campaign",
            guest.to_str().unwrap(),
            "--gens",
            "1",
            "--timeout-secs",
            "600",
            "--out-dir",
            out.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(fs::File::create(directory.path().join("campaign.stderr")).unwrap())
        .spawn()
        .unwrap();

    // The generation is the campaign's child that leads its own process group;
    // it is in flight once its guest runs in that group too.
    let deadline = Instant::now() + Duration::from_secs(120);
    let generation = loop {
        let processes = process_table();
        let in_flight = processes.iter().find(|leader| {
            leader.ppid == campaign.id()
                && leader.pgid == leader.pid
                && processes
                    .iter()
                    .any(|member| member.ppid == leader.pid && member.pgid == leader.pid)
        });
        if let Some(leader) = in_flight {
            break leader.pid;
        }
        let ended = campaign.try_wait().unwrap();
        if ended.is_some() || Instant::now() >= deadline {
            let _ = campaign.kill();
            panic!(
                "the campaign never had a generation's guest running (ended: {ended:?}):\n{}",
                fs::read_to_string(directory.path().join("campaign.stderr")).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    campaign.kill().unwrap();
    campaign.wait().unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    while process_group_alive(generation) {
        if Instant::now() >= deadline {
            crate::common::process_group::kill(generation).expect("clean up the orphaned group");
            panic!("the generation's process group {generation} outlived its killed campaign");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct HostProcess {
    pid: u32,
    ppid: u32,
    pgid: u32,
}

/// Every host process, read from `ps` (POSIX, the same on Linux and macOS).
fn process_table() -> Vec<HostProcess> {
    let listing = Command::new("ps")
        .args(["-A", "-o", "pid=", "-o", "ppid=", "-o", "pgid="])
        .output()
        .expect("run ps");
    String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter_map(|line| {
            let fields = line
                .split_whitespace()
                .map(|field| field.parse::<u32>().ok())
                .collect::<Option<Vec<_>>>()?;
            match fields[..] {
                [pid, ppid, pgid] => Some(HostProcess { pid, ppid, pgid }),
                _ => None,
            }
        })
        .collect()
}

/// Whether any process remains in the process group `pgid`.
fn process_group_alive(pgid: u32) -> bool {
    unsafe extern "C" {
        #[link_name = "kill"]
        fn host_kill(pid: i32, signal: i32) -> i32;
    }
    // SAFETY: signal 0 delivers nothing; it only probes for group members.
    let probed = unsafe { host_kill(-(pgid as i32), 0) };
    probed == 0
        || std::io::Error::last_os_error().raw_os_error()
            != Some(crate::common::process_group::ESRCH)
}
