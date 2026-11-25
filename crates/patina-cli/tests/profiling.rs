//! End-to-end tests for Patina's deterministic guest profiling suite:
//! 1. 4-bucket attribution, Perfetto trace JSON, memory timeline, virtual tail latency, and HTML.
//! 2. 100% deterministic compute-point CPU flamegraphs (`--profile-cpu`) with zero perturbation to
//!    `boundary.log` and full ELF symbol resolution (without `perf_event_open`).
//! 3. Black-box ELF-rewriter edge-coverage bitmap (`--coverage`) on `patina run` and `patina batch`.
//! 4. Sweep HTML dashboards and the built-in `--serve` HTTP server.

use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const GUEST_C: &str = r#"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static volatile uint64_t sink = 0;

__attribute__((noinline))
static uint64_t hot_compute_mix(uint64_t x, int iters) {
    uint64_t acc = x ^ 0x9e3779b97f4a7c15ULL;
    for (int i = 0; i < iters; i++) {
        acc ^= acc << 13;
        acc ^= acc >> 7;
        acc ^= acc << 17;
        acc += (uint64_t)i * 31ULL;
    }
    sink ^= acc;
    return acc;
}

__attribute__((noinline))
static uint64_t hot_compute_outer(int rounds) {
    uint64_t total = 1;
    for (int r = 0; r < rounds; r++) {
        total += hot_compute_mix(total + (uint64_t)r, 600);
    }
    return total;
}

__attribute__((noinline))
static uint64_t branch_alpha(uint64_t v) {
    uint64_t s = 0;
    for (int i = 0; i < 64; i++) {
        if ((i & 1) == 0) {
            s += (v ^ (uint64_t)i) * 3ULL;
        } else {
            s ^= (v + (uint64_t)i) * 7ULL;
        }
    }
    return s;
}

__attribute__((noinline))
static uint64_t branch_beta(uint64_t v) {
    uint64_t s = 17;
    for (int i = 0; i < 64; i++) {
        if ((i % 3) == 0) {
            s = (s << 2) ^ (v + (uint64_t)i);
        } else if ((i % 3) == 1) {
            s += (v >> 1) + (uint64_t)i;
        } else {
            s ^= (s >> 3) + 11ULL;
        }
    }
    return s;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "alpha";

    // Allocate a 512 KiB mapping so memory timeline & peak bytes are observable.
    size_t map_len = 512 * 1024;
    void *buf = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) return 2;
    memset(buf, 0x5a, map_len);

    // Deterministic compute workload across nested named functions.
    uint64_t h = hot_compute_outer(25);
    if (strcmp(mode, "beta") == 0) {
        h ^= branch_beta(h);
    } else {
        h ^= branch_alpha(h);
    }

    // File I/O + fsync workload for logical I/O & tail-latency buckets.
    int fd = open("/work/prof_out.bin", O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) return 3;
    char block[1024];
    memset(block, (int)(h & 0xff), sizeof(block));
    for (int i = 0; i < 6; i++) {
        if (write(fd, block, sizeof(block)) != (ssize_t)sizeof(block)) return 4;
        if (fsync(fd) != 0) return 5;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) return 6;
    char rbuf[1024];
    if (read(fd, rbuf, sizeof(rbuf)) != (ssize_t)sizeof(rbuf)) return 7;
    close(fd);

    munmap(buf, map_len);
    printf("ok %s %llu\n", mode, (unsigned long long)(h ^ (uint64_t)(unsigned char)rbuf[0]));
    return 0;
}
"#;

fn patina_bin() -> &'static str {
    env!("CARGO_BIN_EXE_patina")
}

fn compile_guest(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mkdir");
    let src = dir.join("guest_prof.c");
    let bin = dir.join("guest_prof");
    std::fs::write(&src, GUEST_C).expect("write guest_prof.c");
    let st = Command::new("cc")
        .args([
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-Wall",
            "-Wextra",
            "-o",
        ])
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("cc");
    assert!(
        st.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    bin
}

fn run_patina(args: &[&str]) -> std::process::Output {
    Command::new(patina_bin())
        .args(args)
        .output()
        .expect("patina")
}

#[test]
fn profiling_suite_end_to_end() {
    let root = std::env::temp_dir().join(format!("patina-prof-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest = compile_guest(&root);
    let guest_s = guest.to_str().unwrap();

    // ------------------------------------------------------------------------
    // 1. Baseline run (no profiling / coverage flags) + offline `patina inspect`
    // ------------------------------------------------------------------------
    let base_dir = root.join("run-base");
    let base_s = base_dir.to_str().unwrap();
    let out = run_patina(&[
        "run", "--seed", "11", "--out", base_s, "--", guest_s, "alpha",
    ]);
    assert!(
        out.status.success(),
        "baseline run failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !base_dir.join("boot-1/cpu_profile.bin").exists(),
        "default run must not create cpu_profile.bin"
    );
    let base_res: Value =
        serde_json::from_str(&std::fs::read_to_string(base_dir.join("result.json")).unwrap())
            .unwrap();
    assert!(
        base_res.get("coverage").is_none(),
        "default run must not emit coverage in result.json"
    );
    let base_log = std::fs::read(base_dir.join("boot-1/boundary.log")).unwrap();

    // Summary format
    let sum = run_patina(&["inspect", "profile", base_s]);
    assert!(
        sum.status.success(),
        "inspect profile failed: {}",
        String::from_utf8_lossy(&sum.stderr)
    );
    let sum_txt = String::from_utf8_lossy(&sum.stdout);
    assert!(sum_txt.contains("1. Guest User Compute"));
    assert!(sum_txt.contains("2. Logical I/O & Syscall Work"));
    assert!(sum_txt.contains("3. Modeled Virtual Latency"));
    assert!(sum_txt.contains("4. Patina Runtime Tax"));

    // JSON format: 4 buckets, memory peak, virtual latency percentiles
    let pj = run_patina(&["inspect", "profile", base_s, "--format", "json"]);
    assert!(pj.status.success());
    let prof: Value = serde_json::from_slice(&pj.stdout).expect("profile json");
    assert!(prof["logical_io"]["write_bytes"].as_u64().unwrap() >= 6 * 1024);
    assert!(prof["logical_io"]["read_bytes"].as_u64().unwrap() >= 1024);
    assert!(prof["logical_io"]["fsync_ops"].as_u64().unwrap() >= 6);
    assert!(
        prof["memory"]["peak_mapped_bytes"].as_u64().unwrap() >= 512 * 1024,
        "memory peak should capture 512 KiB mmap: {}",
        prof["memory"]
    );
    assert!(
        prof["virtual_latency"]["distributions"]["fsync"]["count"]
            .as_u64()
            .unwrap_or(0)
            >= 6
    );
    assert!(
        prof["virtual_latency"]["distributions"]["read_write"]["count"]
            .as_u64()
            .unwrap_or(0)
            >= 6
    );

    // Perfetto / Chrome Trace Event JSON
    let pt = run_patina(&["inspect", "trace", base_s]);
    assert!(pt.status.success());
    let trace: Value = serde_json::from_slice(&pt.stdout).expect("trace json");
    let events = trace["traceEvents"].as_array().expect("traceEvents array");
    assert!(!events.is_empty());
    assert!(events.iter().any(|e| e["ph"] == "X"));
    assert!(
        events
            .iter()
            .any(|e| e["ph"] == "C" && e["name"] == "guest_memory_bytes"),
        "Perfetto trace must include guest_memory_bytes memory counter track"
    );

    // Self-contained zero-CDN HTML
    let html_path = root.join("run.html");
    let ph = run_patina(&[
        "inspect",
        "html",
        base_s,
        "--out",
        html_path.to_str().unwrap(),
    ]);
    assert!(ph.status.success());
    let html = std::fs::read_to_string(&html_path).unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("patina-profile-data"));
    assert!(html.contains("patina-trace-data"));
    assert!(html.contains("Download Perfetto Trace JSON"));
    assert!(
        !html.contains("https://") && !html.contains("http://"),
        "HTML dashboard must be 100% self-contained with zero CDN links"
    );

    // ------------------------------------------------------------------------
    // 2. 100% Deterministic Compute-Point CPU Flamegraphs (`--profile-cpu`)
    // ------------------------------------------------------------------------
    let cpu1 = root.join("run-cpu-1");
    let cpu2 = root.join("run-cpu-2");
    for d in [&cpu1, &cpu2] {
        let r = run_patina(&[
            "run",
            "--seed",
            "11",
            "--profile-cpu=20",
            "--out",
            d.to_str().unwrap(),
            "--",
            guest_s,
            "alpha",
        ]);
        assert!(
            r.status.success(),
            "profile-cpu run failed: {}{}",
            String::from_utf8_lossy(&r.stdout),
            String::from_utf8_lossy(&r.stderr)
        );
    }

    // boundary.log MUST be bit-for-bit identical with and without --profile-cpu!
    let cpu1_log = std::fs::read(cpu1.join("boot-1/boundary.log")).unwrap();
    let cpu2_log = std::fs::read(cpu2.join("boot-1/boundary.log")).unwrap();
    assert_eq!(
        base_log, cpu1_log,
        "--profile-cpu must never perturb boundary.log"
    );
    assert_eq!(cpu1_log, cpu2_log);

    // cpu_profile.bin MUST be non-empty and 100% bit-for-bit identical across runs!
    let raw1 = std::fs::read(cpu1.join("boot-1/cpu_profile.bin")).expect("cpu_profile.bin");
    let raw2 = std::fs::read(cpu2.join("boot-1/cpu_profile.bin")).expect("cpu_profile.bin");
    assert!(raw1.len() > 16, "cpu_profile.bin should contain samples");
    assert_eq!(
        raw1, raw2,
        "same seed must produce 100% bit-for-bit identical cpu_profile.bin"
    );

    // Folded flamegraph MUST be bit-for-bit identical, symbolized, and free of patina-rt frames
    let f1 = run_patina(&["inspect", "folded", cpu1.to_str().unwrap()]);
    let f2 = run_patina(&["inspect", "folded", cpu2.to_str().unwrap()]);
    assert!(f1.status.success() && f2.status.success());
    assert_eq!(
        f1.stdout, f2.stdout,
        "folded flamegraph must be 100% bit-for-bit identical"
    );
    let folded = String::from_utf8_lossy(&f1.stdout);
    assert!(
        folded.contains("hot_compute_mix") || folded.contains("hot_compute_outer"),
        "folded stacks must resolve guest symbols, got:\n{folded}"
    );
    assert!(
        !folded.contains("0x7f00000"),
        "folded stacks must never leak patina-rt addresses"
    );

    // `patina replay RUNDIR --profile-cpu=20` must succeed and report identical
    let rep = run_patina(&["replay", base_s, "--profile-cpu=20"]);
    assert!(
        rep.status.success(),
        "replay with --profile-cpu failed: {}{}",
        String::from_utf8_lossy(&rep.stdout),
        String::from_utf8_lossy(&rep.stderr)
    );
    assert!(String::from_utf8_lossy(&rep.stdout).contains("identical"));

    // ------------------------------------------------------------------------
    // 3. Black-Box ELF-Rewriter Edge Coverage (`--coverage`) on run & batch
    // ------------------------------------------------------------------------
    let cov_a1 = root.join("run-cov-a1");
    let cov_a2 = root.join("run-cov-a2");
    let cov_b = root.join("run-cov-b");
    for (d, mode) in [(&cov_a1, "alpha"), (&cov_a2, "alpha"), (&cov_b, "beta")] {
        let r = run_patina(&[
            "run",
            "--seed",
            "31",
            "--coverage",
            "--out",
            d.to_str().unwrap(),
            "--",
            guest_s,
            mode,
        ]);
        assert!(
            r.status.success(),
            "coverage run ({mode}) failed: {}{}",
            String::from_utf8_lossy(&r.stdout),
            String::from_utf8_lossy(&r.stderr)
        );
    }
    let ra1: Value =
        serde_json::from_str(&std::fs::read_to_string(cov_a1.join("result.json")).unwrap())
            .unwrap();
    let ra2: Value =
        serde_json::from_str(&std::fs::read_to_string(cov_a2.join("result.json")).unwrap())
            .unwrap();
    let rb: Value =
        serde_json::from_str(&std::fs::read_to_string(cov_b.join("result.json")).unwrap()).unwrap();

    assert!(ra1["coverage"]["edges_hit"].as_u64().unwrap() > 0);
    assert!(ra1["coverage"]["total_hits"].as_u64().unwrap() > 0);
    assert!(!ra1["coverage"]["edge_hashes"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        ra1["coverage"], ra2["coverage"],
        "same seed + input must produce identical edge coverage"
    );
    assert_ne!(
        ra1["coverage"]["edge_hashes"], rb["coverage"]["edge_hashes"],
        "different guest branches must produce different edge coverage hashes"
    );

    // `patina batch --coverage` NDJSON response must include `coverage`
    let mut batch = Command::new(patina_bin())
        .args(["batch", "--coverage", "--", guest_s, "alpha"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batch");
    {
        let mut stdin = batch.stdin.take().unwrap();
        writeln!(stdin, r#"{{"seed": 31}}"#).unwrap();
    }
    let bout = batch.wait_with_output().expect("batch output");
    assert!(
        bout.status.success(),
        "batch --coverage failed: {}",
        String::from_utf8_lossy(&bout.stderr)
    );
    let b_line = String::from_utf8_lossy(&bout.stdout);
    let b_val: Value = serde_json::from_str(b_line.trim()).expect("batch ndjson");
    assert_eq!(
        b_val["coverage"]["edges_hit"], ra1["coverage"]["edges_hit"],
        "batch --coverage must report the same edge count as patina run --coverage"
    );
    assert_eq!(
        b_val["coverage"]["edge_hashes"], ra1["coverage"]["edge_hashes"],
        "batch --coverage must report identical edge_hashes"
    );

    // ------------------------------------------------------------------------
    // 4. Sweep HTML dashboard & `--serve` local HTTP server
    // ------------------------------------------------------------------------
    let sweep_dir = root.join("sweep-out");
    let sw = run_patina(&[
        "sweep",
        "--seeds",
        "1..4",
        "--out",
        sweep_dir.to_str().unwrap(),
        "--",
        guest_s,
        "alpha",
    ]);
    assert!(
        sw.status.success(),
        "sweep failed: {}{}",
        String::from_utf8_lossy(&sw.stdout),
        String::from_utf8_lossy(&sw.stderr)
    );
    let sw_html_path = root.join("sweep.html");
    let swh = run_patina(&[
        "inspect",
        "html",
        sweep_dir.to_str().unwrap(),
        "--out",
        sw_html_path.to_str().unwrap(),
    ]);
    assert!(
        swh.status.success(),
        "sweep inspect html failed: {}",
        String::from_utf8_lossy(&swh.stderr)
    );
    let sw_html = std::fs::read_to_string(&sw_html_path).unwrap();
    assert!(sw_html.contains("Patina Sweep / Campaign Dashboard"));
    assert!(sw_html.contains("patina-sweep-data"));
    assert!(!sw_html.contains("https://") && !sw_html.contains("http://"));

    // Spawn `patina inspect serve --addr 127.0.0.1:0 <cov_a1>` and verify HTTP routes
    let mut srv = Command::new(patina_bin())
        .args([
            "inspect",
            "serve",
            "--addr",
            "127.0.0.1:0",
            cov_a1.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn inspect serve");
    let mut stderr = BufReader::new(srv.stderr.take().unwrap());
    let mut first_line = String::new();
    stderr.read_line(&mut first_line).expect("read serve URL");
    let addr = first_line
        .trim()
        .split("http://")
        .nth(1)
        .expect("expected http:// URL on stderr")
        .trim_end_matches('/')
        .to_string();

    let http_get = |path: &str| -> String {
        let mut s = TcpStream::connect(&addr).expect("connect --serve");
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        resp
    };

    let r_root = http_get("/");
    assert!(r_root.starts_with("HTTP/1.1 200 OK"));
    assert!(r_root.contains("<!DOCTYPE html>"));

    let r_prof = http_get("/profile.json");
    assert!(r_prof.starts_with("HTTP/1.1 200 OK"));
    let body_p = r_prof.split("\r\n\r\n").nth(1).unwrap();
    let _: Value = serde_json::from_str(body_p).expect("/profile.json valid JSON");

    let r_trace = http_get("/trace.json");
    assert!(r_trace.starts_with("HTTP/1.1 200 OK"));
    let body_t = r_trace.split("\r\n\r\n").nth(1).unwrap();
    let tv: Value = serde_json::from_str(body_t).expect("/trace.json valid JSON");
    assert!(tv["traceEvents"].is_array());

    let _ = srv.kill();
    let _ = srv.wait();
    let _ = std::fs::remove_dir_all(&root);
}
