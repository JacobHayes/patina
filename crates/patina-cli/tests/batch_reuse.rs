//! Integration tests for persistent sandbox reuse in `patina batch`:
//! - bit-for-bit identical digests and `boundary.log` compared to cold `patina run`
//!   across run 1, run 2, and run 50 on the same reused worker;
//! - complete inter-run state isolation across `/tmp`, `/work`, `/dev/shm`, `/`, `/etc`,
//!   env/cwd, child processes, pipes, and non-zero exits;
//! - read-only, `:copy`, and nested mounts;
//! - `--timeout` cancellation and clean recovery on the reused worker.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

fn patina_bin() -> &'static str {
    env!("CARGO_BIN_EXE_patina")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "patina-batch-reuse-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create temp dir");
        Self(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_batch(args: &[&str], reqs: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut child = Command::new(patina_bin())
        .arg("batch")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn patina batch");
    {
        let stdin = child.stdin.as_mut().expect("batch stdin");
        for r in reqs {
            writeln!(stdin, "{r}").expect("write batch request");
        }
    }
    let out = child.wait_with_output().expect("wait patina batch");
    assert!(
        out.status.success(),
        "patina batch failed: status={:?}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid JSON response"))
        .collect()
}

fn cold_run(out_dir: &Path, seed: u64, extra_args: &[&str], cmd: &[&str]) -> serde_json::Value {
    let out = Command::new(patina_bin())
        .arg("run")
        .args(["--seed", &seed.to_string(), "--out"])
        .arg(out_dir)
        .args(extra_args)
        .arg("--")
        .args(cmd)
        .output()
        .expect("spawn patina run");
    assert!(
        out.status.success(),
        "patina run failed: status={:?}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&fs::read(out_dir.join("result.json")).expect("read result.json"))
        .expect("parse result.json")
}

#[test]
fn batch_reuse_bit_for_bit_identical_to_run() {
    let tmp = TempDir::new("det");
    let cold_dir = tmp.path().join("cold");
    let cold = cold_run(&cold_dir, 42, &[], &["/bin/true"]);
    let cold_digest = cold["digest"].as_str().expect("cold digest");
    let cold_log = fs::read(cold_dir.join("boot-1/boundary.log")).expect("cold boundary.log");

    let mut reqs = Vec::with_capacity(50);
    for i in 1..=50u64 {
        let mut r = serde_json::json!({ "id": i, "seed": 42 });
        if matches!(i, 1 | 2 | 50) {
            r["out"] = serde_json::json!(tmp.path().join(format!("b-{i}")));
        }
        reqs.push(r);
    }

    let resps = run_batch(&["-j", "1", "--", "/bin/true"], &reqs);
    assert_eq!(resps.len(), 50);
    for r in &resps {
        assert_eq!(r["outcome"], "ok", "unexpected response: {r}");
        assert_eq!(r["digest"], cold_digest, "digest mismatch on {r}");
    }
    for k in [1u64, 2, 50] {
        let log = fs::read(tmp.path().join(format!("b-{k}/boot-1/boundary.log")))
            .expect("batch boundary.log");
        assert_eq!(
            log, cold_log,
            "run {k} boundary.log differs from cold patina run"
        );
    }
}

#[test]
fn batch_reuse_state_isolation_across_runs() {
    let tmp = TempDir::new("iso");
    let probe = "ls -A /tmp /work /dev/shm; ls /dirty_root /etc/leak_etc 2>&1 || true; \
                 stat / /etc /etc/passwd /etc/ld.so.cache /work /tmp /dev /dev/shm; \
                 cat /proc/self/mountinfo; echo pid=$$ pwd=$PWD foo=${FOO:-unset}";

    let cold_dir = tmp.path().join("cold");
    let cold = cold_run(&cold_dir, 99, &[], &["/bin/sh", "-c", probe]);
    let cold_digest = cold["digest"].as_str().expect("cold digest");
    let cold_log = fs::read(cold_dir.join("boot-1/boundary.log")).expect("cold boundary.log");
    let cold_stdout = fs::read(cold_dir.join("boot-1/stdout")).expect("cold stdout");

    let after_tmp = tmp.path().join("after-tmp");
    let after_root = tmp.path().join("after-root");
    let reqs = vec![
        serde_json::json!({
            "id": 1,
            "seed": 1,
            "args": ["touch /tmp/leak1 /work/leak1; (sleep 0.01 & wait); echo hi | cat >/dev/null; cd /tmp; export FOO=bar; exit 7"]
        }),
        serde_json::json!({
            "id": 2,
            "seed": 99,
            "args": [probe],
            "out": after_tmp,
        }),
        serde_json::json!({
            "id": 3,
            "seed": 3,
            "args": ["touch /dev/shm/leak_shm /dirty_root /etc/leak_etc /tmp/leak3 /work/leak3; exit 9"]
        }),
        serde_json::json!({
            "id": 4,
            "seed": 99,
            "args": [probe],
            "out": after_root,
        }),
    ];

    let resps = run_batch(&["-j", "1", "--", "/bin/sh", "-c"], &reqs);
    assert_eq!(resps.len(), 4);
    assert_eq!(resps[0]["outcome"], "failure");
    assert_eq!(resps[1]["outcome"], "ok");
    assert_eq!(resps[1]["digest"], cold_digest);
    assert_eq!(resps[2]["outcome"], "failure");
    assert_eq!(resps[3]["outcome"], "ok");
    assert_eq!(resps[3]["digest"], cold_digest);

    for (label, dir) in [("after-tmp", &after_tmp), ("after-root", &after_root)] {
        assert_eq!(
            fs::read(dir.join("boot-1/boundary.log")).expect("batch boundary.log"),
            cold_log,
            "{label}: boundary.log differs from cold patina run"
        );
        assert_eq!(
            fs::read(dir.join("boot-1/stdout")).expect("batch stdout"),
            cold_stdout,
            "{label}: stdout differs from cold patina run"
        );
    }
}

#[test]
fn batch_reuse_mounts_ro_copy_and_nested() {
    let tmp = TempDir::new("mnt");
    let ro_dir = tmp.path().join("ro");
    let cp_dir = tmp.path().join("cp");
    let sub_dir = tmp.path().join("sub");
    fs::create_dir_all(&ro_dir).unwrap();
    fs::create_dir_all(&cp_dir).unwrap();
    fs::create_dir_all(&sub_dir).unwrap();
    fs::write(ro_dir.join("f.txt"), "hello-ro\n").unwrap();
    fs::write(cp_dir.join("c.txt"), "hello-copy\n").unwrap();
    fs::write(sub_dir.join("s.txt"), "hello-sub\n").unwrap();

    let m_ro = format!("{}:/mnt/ro", ro_dir.display());
    let m_cp = format!("{}:/mnt/cp:copy", cp_dir.display());
    let m_sub = format!("{}:/guest/sub", sub_dir.display());
    let script = "cat /mnt/ro/f.txt /mnt/cp/c.txt /guest/sub/s.txt; echo dirty >> /mnt/cp/c.txt; cat /mnt/cp/c.txt";

    let cold_dir = tmp.path().join("cold");
    let cold = cold_run(
        &cold_dir,
        5,
        &["--mount", &m_ro, "--mount", &m_cp, "--mount", &m_sub],
        &["/bin/sh", "-c", script],
    );
    let cold_digest = cold["digest"].as_str().expect("cold digest");
    let cold_log = fs::read(cold_dir.join("boot-1/boundary.log")).expect("cold boundary.log");
    let cold_stdout = fs::read(cold_dir.join("boot-1/stdout")).expect("cold stdout");

    let d1 = tmp.path().join("m1");
    let d2 = tmp.path().join("m2");
    let reqs = vec![
        serde_json::json!({ "id": 1, "seed": 5, "out": d1 }),
        serde_json::json!({ "id": 2, "seed": 5, "out": d2 }),
    ];
    let resps = run_batch(
        &[
            "-j", "1", "--mount", &m_ro, "--mount", &m_cp, "--mount", &m_sub, "--", "/bin/sh",
            "-c", script,
        ],
        &reqs,
    );
    assert_eq!(resps.len(), 2);
    for (r, dir) in resps.iter().zip([&d1, &d2]) {
        assert_eq!(r["outcome"], "ok", "{r}");
        assert_eq!(r["digest"], cold_digest, "{r}");
        assert_eq!(fs::read(dir.join("boot-1/boundary.log")).unwrap(), cold_log);
        assert_eq!(fs::read(dir.join("boot-1/stdout")).unwrap(), cold_stdout);
    }
}

#[test]
fn batch_reuse_timeout_cancellation_and_recovery() {
    let tmp = TempDir::new("timeout");
    let cold_dir = tmp.path().join("cold");
    let cold = cold_run(&cold_dir, 99, &[], &["/bin/sh", "-c", "echo ok"]);
    let cold_digest = cold["digest"].as_str().expect("cold digest");
    let cold_log = fs::read(cold_dir.join("boot-1/boundary.log")).expect("cold boundary.log");

    let after = tmp.path().join("after");
    let reqs = vec![
        serde_json::json!({ "id": 1, "seed": 1, "args": ["while :; do :; done"] }),
        serde_json::json!({ "id": 2, "seed": 99, "args": ["echo ok"], "out": after }),
    ];
    let resps = run_batch(&["-j", "1", "--timeout", "1", "--", "/bin/sh", "-c"], &reqs);
    assert_eq!(resps.len(), 2);
    assert_eq!(resps[0]["outcome"], "timeout", "{}", resps[0]);
    assert_eq!(resps[1]["outcome"], "ok", "{}", resps[1]);
    assert_eq!(resps[1]["digest"], cold_digest);
    assert_eq!(
        fs::read(after.join("boot-1/boundary.log")).unwrap(),
        cold_log
    );
}
