//! `patina batch`: a persistent multi-core worker pool that amortizes CLI startup, preflight,
//! program hashing, and rewrite plan warming across many deterministic runs driven over NDJSON
//! stdin/stdout (e.g. by an outer-loop fuzzer or test harness).
//!
//! Protocol (one JSON object per line):
//! - Request on stdin:
//!   `{"id": 1, "seed": 7, "args": ["foo", "bar"], "out": "/optional/keep/dir"}`
//!   (`id` defaults to the 0-based line index; `seed` defaults to `--seed`; `args` defaults to `[]`).
//! - Response on stdout:
//!   `{"id": 1, "seed": 7, "outcome": "ok", "stop": "exit", "digest": "...", "exit": 0, ...}`
//!   (emitted as each worker completes; callers match by `id`).

use crate::cli::Args;
use crate::config::Opts;
use crate::{error, internal, Fail};
use serde::Deserialize;
use serde_json::json;
use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug, Deserialize)]
struct BatchReq {
    id: Option<u64>,
    seed: Option<u64>,
    #[serde(default)]
    args: Vec<String>,
    out: Option<String>,
}

struct WorkItem {
    seq: u64,
    req: BatchReq,
}

struct Queue {
    items: Mutex<(VecDeque<WorkItem>, bool)>,
    cv: Condvar,
}

impl Queue {
    fn new() -> Queue {
        Queue {
            items: Mutex::new((VecDeque::new(), false)),
            cv: Condvar::new(),
        }
    }

    fn push(&self, item: WorkItem) {
        let mut g = self.items.lock().unwrap();
        g.0.push_back(item);
        self.cv.notify_one();
    }

    fn close(&self) {
        let mut g = self.items.lock().unwrap();
        g.1 = true;
        self.cv.notify_all();
    }

    fn pop(&self) -> Option<WorkItem> {
        let mut g = self.items.lock().unwrap();
        loop {
            if let Some(item) = g.0.pop_front() {
                return Some(item);
            }
            if g.1 {
                return None;
            }
            g = self.cv.wait(g).unwrap();
        }
    }
}

pub fn main(a: &Args) -> Result<ExitCode, Fail> {
    let cfg = crate::config::resolve(a).map_err(error)?;
    let base_opts = Arc::new(cfg.opts().map_err(error)?);
    crate::launch::preflight(&base_opts).map_err(error)?;

    // Warm runtime file, sandbox static caches, and rewrite planner ONCE.
    let _ = crate::launch::rt_file().map_err(internal)?;
    let _ = crate::launch::layout(&base_opts, base_opts.cfg.disk.as_deref()).map_err(internal)?;
    let planner = Arc::new(crate::launcher::boots::warm_planner(&base_opts).map_err(internal)?);

    let cpus = crate::launch::allowed_cpus();
    let default_jobs = cpus.len().min(8).max(1);
    let jobs = match a.num::<usize>("--jobs").map_err(error)? {
        Some(0) => return Err(error("--jobs must be at least 1".into())),
        Some(j) => j.min(cpus.len().max(1)),
        None => default_jobs,
    };

    let tmp_root = Arc::new(std::env::temp_dir().join(format!("patina-batch-{}", std::process::id())));
    fs::create_dir_all(&*tmp_root)
        .map_err(|e| internal(format!("create {}: {e}", tmp_root.display())))?;

    let queue = Arc::new(Queue::new());
    let stdout = Arc::new(Mutex::new(BufWriter::new(io::stdout())));
    let seq_counter = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(jobs);
    for worker_idx in 0..jobs {
        let cpu = cpus[worker_idx % cpus.len()];
        let q = Arc::clone(&queue);
        let base = Arc::clone(&base_opts);
        let planner = Arc::clone(&planner);
        let out_lock = Arc::clone(&stdout);
        let tmp_root = Arc::clone(&tmp_root);
        let h = std::thread::Builder::new()
            .name(format!("patina-batch-{worker_idx}"))
            .spawn(move || {
                while let Some(item) = q.pop() {
                    let id = item.req.id.unwrap_or(item.seq);
                    let seed = item.req.seed.unwrap_or(base.cfg.seed);
                    let resp = run_item(
                        id,
                        seed,
                        &item.req,
                        item.seq,
                        cpu,
                        &base,
                        planner.as_ref().as_ref(),
                        &tmp_root,
                    );
                    let mut w = out_lock.lock().unwrap();
                    let _ = serde_json::to_writer(&mut *w, &resp);
                    let _ = w.write_all(b"\n");
                    let _ = w.flush();
                }
            })
            .map_err(|e| internal(format!("spawn batch worker: {e}")))?;
        handles.push(h);
    }

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                queue.close();
                for h in handles {
                    let _ = h.join();
                }
                let _ = fs::remove_dir_all(&*tmp_root);
                return Err(internal(format!("batch stdin: {e}")));
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
        match serde_json::from_str::<BatchReq>(trimmed) {
            Ok(req) => queue.push(WorkItem { seq, req }),
            Err(e) => {
                let mut w = stdout.lock().unwrap();
                let resp = json!({
                    "id": seq,
                    "outcome": "error",
                    "error": format!("invalid JSON request: {e}"),
                });
                let _ = serde_json::to_writer(&mut *w, &resp);
                let _ = w.write_all(b"\n");
                let _ = w.flush();
            }
        }
    }

    queue.close();
    for h in handles {
        let _ = h.join();
    }
    let _ = fs::remove_dir_all(&*tmp_root);
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::too_many_arguments)]
fn run_item(
    id: u64,
    seed: u64,
    req: &BatchReq,
    seq: u64,
    cpu: usize,
    base: &Opts,
    planner: Option<&crate::launcher::plans::Planner>,
    tmp_root: &std::path::Path,
) -> serde_json::Value {
    let opts = match base.for_batch(seed, &req.args) {
        Ok(o) => o,
        Err(e) => {
            return json!({
                "id": id,
                "seed": seed,
                "outcome": "error",
                "error": e,
            })
        }
    };

    let (run_dir, keep) = match &req.out {
        Some(p) => {
            let dir = PathBuf::from(crate::config::logical(p));
            if let Err(e) = crate::replay::clear_out(&dir) {
                return json!({
                    "id": id,
                    "seed": seed,
                    "outcome": "error",
                    "error": e,
                });
            }
            (dir, true)
        }
        None => (tmp_root.join(format!("r-{seq}")), false),
    };

    if keep {
        if let Err(e) = fs::create_dir_all(&run_dir)
            .map_err(|e| format!("{}: {e}", run_dir.display()))
            .and_then(|_| {
                crate::result::write_json(&run_dir.join("run.json"), &crate::result::run_json(&opts)?)
            })
        {
            return json!({
                "id": id,
                "seed": seed,
                "outcome": "error",
                "error": e,
            });
        }
    }

    let end = match crate::launcher::boots::run_chain_with_planner(
        &opts, &run_dir, cpu, false, planner,
    ) {
        Ok(end) => end,
        Err(e) => {
            if !keep {
                let _ = fs::remove_dir_all(&run_dir);
            }
            return json!({
                "id": id,
                "seed": seed,
                "outcome": "internal",
                "error": e,
            });
        }
    };

    let c = crate::result::classified(&end);
    let mut r = crate::result::result_json(&end, &c);
    if keep {
        r["signature"] = crate::signature::of(&r, &run_dir);
        let _ = crate::result::write_json(&run_dir.join("result.json"), &r);
    } else {
        let _ = fs::remove_dir_all(&run_dir);
    }

    let mut resp = json!({
        "id": id,
        "seed": seed,
        "outcome": r["outcome"],
        "stop": r["stop"],
        "digest": r["digest"],
        "exit": r["exit"],
        "wall_ms": r["wall_ms"],
    });
    if let Some(sdk_json) = r.get("sdk") {
        resp["sdk"] = sdk_json.clone();
    }
    if keep {
        resp["dir"] = json!(run_dir);
    }
    resp
}
