//! Integration tests for Patina self-profiling (`PATINA_PROFILE`, `PATINA_PROFILE_OUT`,
//! and `--features profile` inner-loop counters in `patina-rt`).

use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

fn patina_bin() -> &'static str {
    env!("CARGO_BIN_EXE_patina")
}

fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!(
        "patina-self-profile-{}-{}-{id}",
        std::process::id(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn unset_vs_enabled_produces_identical_digest_and_boundary_log() {
    let root = temp_dir("determinism");
    let out_plain = root.join("plain");
    let out_prof = root.join("prof");
    let trace = root.join("trace.json");

    // 1. Default run with PATINA_PROFILE unset.
    let plain = Command::new(patina_bin())
        .env_remove("PATINA_PROFILE")
        .env_remove("PATINA_PROFILE_OUT")
        .args([
            "run",
            "--seed",
            "7",
            "--format",
            "json",
            "--out",
            out_plain.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "echo hello-self-profile",
        ])
        .output()
        .expect("run patina plain");
    assert!(
        plain.status.success(),
        "plain run failed: {}",
        String::from_utf8_lossy(&plain.stderr)
    );
    let plain_stderr = String::from_utf8_lossy(&plain.stderr);
    assert!(
        !plain_stderr.contains("patina-profile:"),
        "unexpected profile output when unset: {plain_stderr}"
    );
    let plain_json: Value = serde_json::from_slice(&plain.stdout).unwrap();
    assert!(
        plain_json.get("timing").is_none(),
        "result.json must not contain timing when PATINA_PROFILE is unset"
    );
    let plain_file_json: Value =
        serde_json::from_str(&std::fs::read_to_string(out_plain.join("result.json")).unwrap())
            .unwrap();
    assert!(plain_file_json.get("timing").is_none());

    // 2. Profiled run with PATINA_PROFILE=1 and PATINA_PROFILE_OUT.
    let prof = Command::new(patina_bin())
        .env("PATINA_PROFILE", "1")
        .env("PATINA_PROFILE_OUT", &trace)
        .args([
            "run",
            "--seed",
            "7",
            "--format",
            "json",
            "--out",
            out_prof.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "echo hello-self-profile",
        ])
        .output()
        .expect("run patina profiled");
    assert!(
        prof.status.success(),
        "profiled run failed: {}",
        String::from_utf8_lossy(&prof.stderr)
    );
    let prof_stderr = String::from_utf8_lossy(&prof.stderr);
    assert!(
        prof_stderr.contains("patina-profile: run seed=7"),
        "missing waterfall header on stderr: {prof_stderr}"
    );
    assert!(
        prof_stderr.contains("sandbox_mount_setup") && prof_stderr.contains("guest_exec"),
        "missing expected coarse phases on stderr: {prof_stderr}"
    );

    let prof_json: Value = serde_json::from_slice(&prof.stdout).unwrap();
    // Deterministic digest and boundary.log must be bit-for-bit identical!
    assert_eq!(plain_json["digest"], prof_json["digest"]);
    assert_eq!(
        std::fs::read(out_plain.join("boot-1/boundary.log")).unwrap(),
        std::fs::read(out_prof.join("boot-1/boundary.log")).unwrap(),
        "boundary.log must be byte-identical with PATINA_PROFILE=1"
    );

    // Structured timing object attached when enabled.
    let timing = prof_json
        .get("timing")
        .expect("timing missing in profiled result.json");
    assert!(timing["total_ms"].as_f64().unwrap() > 0.0);
    assert!(timing["phases"].as_array().unwrap().len() >= 10);
    assert_eq!(timing["boots"].as_array().unwrap().len(), 1);

    // Chrome Trace Event JSON written to PATINA_PROFILE_OUT.
    let trace_doc: Value = serde_json::from_str(&std::fs::read_to_string(&trace).unwrap()).unwrap();
    assert_eq!(trace_doc["displayTimeUnit"], "ms");
    let events = trace_doc["traceEvents"].as_array().unwrap();
    assert!(
        events.len() >= 10,
        "expected >=10 traceEvents, got {}",
        events.len()
    );
    assert!(events.iter().any(|e| e["name"] == "sandbox_mount_setup"));
    assert!(events.iter().any(|e| e["name"] == "guest_exec"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn json_mode_on_run_emits_valid_json_on_stderr() {
    let root = temp_dir("json-mode");
    let out = root.join("out");
    let res = Command::new(patina_bin())
        .env("PATINA_PROFILE", "json")
        .env_remove("PATINA_PROFILE_OUT")
        .args([
            "run",
            "--seed",
            "3",
            "--out",
            out.to_str().unwrap(),
            "--",
            "/bin/true",
        ])
        .output()
        .expect("run patina json mode");
    assert!(res.status.success());
    let stderr = String::from_utf8_lossy(&res.stderr);
    let v: Value = serde_json::from_str(stderr.trim())
        .unwrap_or_else(|e| panic!("stderr is not valid JSON ({e}): {stderr}"));
    assert_eq!(v["seed"], 3);
    assert!(v["phases"].as_array().unwrap().len() >= 10);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn batch_profiling_emits_per_job_timing_summary_and_trace() {
    let root = temp_dir("batch");
    let trace = root.join("batch-trace.json");

    let run_batch = |profile: Option<&str>, out_trace: Option<&PathBuf>| {
        let mut cmd = Command::new(patina_bin());
        match profile {
            Some(v) => {
                cmd.env("PATINA_PROFILE", v);
            }
            None => {
                cmd.env_remove("PATINA_PROFILE");
            }
        }
        match out_trace {
            Some(p) => {
                cmd.env("PATINA_PROFILE_OUT", p);
            }
            None => {
                cmd.env_remove("PATINA_PROFILE_OUT");
            }
        }
        let mut child = cmd
            .args(["batch", "--jobs", "2", "--", "/bin/true"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn patina batch");
        {
            let mut stdin = child.stdin.take().unwrap();
            writeln!(stdin, r#"{{"id": 1, "seed": 11}}"#).unwrap();
            writeln!(stdin, r#"{{"id": 2, "seed": 12}}"#).unwrap();
            writeln!(stdin, r#"{{"id": 3, "seed": 13}}"#).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "batch failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut lines: Vec<Value> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        lines.sort_by_key(|v| v["id"].as_u64().unwrap());
        (lines, String::from_utf8_lossy(&out.stderr).into_owned())
    };

    let (plain_lines, plain_err) = run_batch(None, None);
    assert_eq!(plain_lines.len(), 3);
    assert!(!plain_err.contains("patina-profile:"));
    for l in &plain_lines {
        assert!(l.get("timing").is_none());
    }

    let (prof_lines, prof_err) = run_batch(Some("1"), Some(&trace));
    assert_eq!(prof_lines.len(), 3);
    assert!(
        prof_err.contains("patina-profile: batch workers=2 jobs=3"),
        "missing batch profile summary: {prof_err}"
    );
    assert!(prof_err.contains("startup:"));
    assert!(prof_err.contains("boot phases"));

    for (p, q) in plain_lines.iter().zip(&prof_lines) {
        assert_eq!(p["digest"], q["digest"], "batch digest must match");
        let t = q.get("timing").expect("batch item missing timing");
        assert!(t["total_ms"].as_f64().unwrap() > 0.0);
        assert_eq!(t["boots"].as_array().unwrap().len(), 1);
    }

    let trace_doc: Value = serde_json::from_str(&std::fs::read_to_string(&trace).unwrap()).unwrap();
    let events = trace_doc["traceEvents"].as_array().unwrap();
    assert!(events.iter().any(|e| e["cat"] == "batch_job"));
    assert_eq!(trace_doc["metadata"]["jobs"], 3);

    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(feature = "profile")]
#[test]
fn feature_profile_populates_rt_inner_loop_counters() {
    let root = temp_dir("rt-profile");
    let out = root.join("out");
    let res = Command::new(patina_bin())
        .env("PATINA_PROFILE", "1")
        .env_remove("PATINA_PROFILE_OUT")
        .args([
            "run",
            "--seed",
            "5",
            "--format",
            "json",
            "--out",
            out.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "echo rt-profile-test && ls /work >/dev/null",
        ])
        .output()
        .expect("run patina with --features profile");
    assert!(
        res.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(
        stderr.contains("inner-loop (patina-rt --features profile):"),
        "missing inner-loop section on stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("top syscalls (by host time):"),
        "missing top syscalls section:\n{stderr}"
    );
    assert!(
        stderr.contains("top supervisor ops (server side):"),
        "missing top supervisor ops section:\n{stderr}"
    );

    let json: Value = serde_json::from_slice(&res.stdout).unwrap();
    let rt = &json["timing"]["rt"];
    assert!(
        rt["sigsys"]["count"].as_u64().unwrap() > 10,
        "expected >10 sigsys traps: {rt}"
    );
    assert!(
        rt["sup_ipc"]["count"].as_u64().unwrap() >= 1,
        "expected >=1 sup_ipc calls: {rt}"
    );
    assert!(
        rt["log"]["trap"]["count"].as_u64().unwrap() > 10,
        "expected >10 log::trap calls: {rt}"
    );
    assert!(
        rt["log"]["append"]["count"].as_u64().unwrap() > 10,
        "expected >10 log::append calls: {rt}"
    );
    assert!(
        !rt["top_syscalls"].as_array().unwrap().is_empty(),
        "expected non-empty top_syscalls: {rt}"
    );
    assert!(
        !rt["top_sup_ops"].as_array().unwrap().is_empty(),
        "expected non-empty top_sup_ops: {rt}"
    );
    // With default `--preempt points`, compute::enter/exit and plans::on_map should be active!
    assert!(
        rt["compute"]["enter"]["count"].as_u64().unwrap() > 0,
        "expected non-zero compute::enter: {rt}"
    );
    assert!(
        rt["compute"]["exit"]["count"].as_u64().unwrap() > 0,
        "expected non-zero compute::exit: {rt}"
    );
    assert!(
        rt["plans"]["on_map"]["count"].as_u64().unwrap() > 0,
        "expected non-zero plans::on_map: {rt}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
