//! `patina verify`: run the same inputs N times, optionally varying things that
//! must not matter, and require identical digests, outcomes and output.

use crate::cli::Res;
use crate::config::Opts;
use crate::launch::{allowed_cpus, default_cpu, run_one};
use crate::outcome::{Classified, Outcome};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Up to six distinct CPUs spread over the allowed set (first, last, middle, ...).
fn cpu_choices() -> Vec<usize> {
    let a = allowed_cpus();
    let n = a.len();
    let mut out = vec![];
    for i in [0, n - 1, n / 2, 1.min(n - 1), n / 3, (2 * n) / 3] {
        if !out.contains(&a[i]) {
            out.push(a[i]);
        }
    }
    out
}

/// Move host-global counters: tmpfs files, pipes and processes created and destroyed on the host.
fn churn() {
    let dir = std::env::var("PATINA_CHURN_DIR").unwrap_or_else(|_| "/dev/shm".into());
    for i in 0..1000 {
        let p = format!("{dir}/patina-churn-{}-{i}", std::process::id());
        let _ = std::fs::write(&p, b"x");
        let _ = std::fs::remove_file(&p);
        let mut fds = [0; 2];
        unsafe {
            if libc::pipe(fds.as_mut_ptr()) == 0 {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            let pid = libc::fork();
            if pid == 0 {
                libc::_exit(0);
            }
            if pid > 0 {
                let mut st = 0;
                libc::waitpid(pid, &mut st, 0);
            }
        }
    }
}

/// Host load while the runs execute: a few busy loops (threads of this process, stopped
/// when the returned guard is dropped). Four by default (`PATINA_LOAD_THREADS` overrides):
/// enough to make the scheduler move the runs around, without starving them when
/// several verifies run at once (2x the core count each took the host to load 250).
struct Load {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Load {
    fn start() -> Load {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let n: usize = std::env::var("PATINA_LOAD_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4);
        let threads = (0..n)
            .map(|_| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut x = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        for i in 0..10_000u64 {
                            x = std::hint::black_box(
                                x.wrapping_mul(6364136223846793005).wrapping_add(i),
                            );
                        }
                    }
                })
            })
            .collect();
        Load { stop, threads }
    }
}

impl Drop for Load {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap_or_default()
}

/// `env`: the launcher's own process state, changed for odd runs and put back for even
/// ones: working directory, environment variables, umask, ignored and blocked signals,
/// `RLIMIT_STACK`/`RLIMIT_CORE` soft limits and the `RLIMIT_NOFILE` hard limit. None of it may
/// reach the guest. Also the state set in the launcher's child before bwrap
/// (`launch::PERTURB`): a leaked descriptor, a controlling terminal and session, the persona,
/// nice, IO priority, scheduling policy, timer slack, THP, OOM adjustment, every soft limit
/// and more ignored signals.
struct EnvState {
    cwd: PathBuf,
    rl: Vec<(i32, libc::rlimit)>,
}

const ENV_RLIMITS: [i32; 3] = [
    libc::RLIMIT_STACK as i32,
    libc::RLIMIT_CORE as i32,
    libc::RLIMIT_NOFILE as i32,
];

fn env_perturb() -> EnvState {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let mut rl = vec![];
    unsafe {
        for r in ENV_RLIMITS {
            let mut v: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(r as _, &mut v);
            rl.push((r, v));
        }
        std::env::set_var("PATINA_ENV_PROBE", "1");
        std::env::set_var("LANG", "de_DE.UTF-8");
        std::env::set_var("TZ", "Pacific/Chatham");
        libc::umask(0o077);
        for s in [
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGHUP,
            libc::SIGUSR1,
            libc::SIGPIPE,
        ] {
            libc::signal(s, libc::SIG_IGN);
        }
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR2);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        for (r, v) in &rl {
            let mut n = *v;
            if *r == libc::RLIMIT_NOFILE as i32 {
                n.rlim_max = n.rlim_max.clamp(4096, 8192);
            } else if *r == libc::RLIMIT_STACK as i32 {
                n.rlim_cur = (n.rlim_cur / 2).max(1 << 20).min(n.rlim_max);
            } else {
                n.rlim_cur = n.rlim_max;
            }
            libc::setrlimit(*r as _, &n);
        }
    }
    let _ = std::env::set_current_dir("/");
    crate::launch::PERTURB.store(true, std::sync::atomic::Ordering::Relaxed);
    EnvState { cwd, rl }
}

fn env_restore(st: EnvState) {
    crate::launch::PERTURB.store(false, std::sync::atomic::Ordering::Relaxed);
    unsafe {
        std::env::remove_var("PATINA_ENV_PROBE");
        std::env::remove_var("LANG");
        std::env::remove_var("TZ");
        libc::umask(0o022);
        for s in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGUSR1] {
            libc::signal(s, libc::SIG_DFL);
        }
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR2);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        for (r, v) in &st.rl {
            // A lowered hard limit cannot be raised again; the soft limits can.
            let mut cur: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(*r as _, &mut cur);
            let n = libc::rlimit {
                rlim_cur: v.rlim_cur.min(cur.rlim_max),
                rlim_max: cur.rlim_max,
            };
            libc::setrlimit(*r as _, &n);
        }
    }
    let _ = std::env::set_current_dir(&st.cwd);
}

struct RunResult {
    oc: crate::result::RunEnd,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    dir: PathBuf,
}

fn one(o: &Opts, dir: PathBuf, cpu: usize, no_pers: bool) -> Res<RunResult> {
    let (oc, _) = run_one(o, &dir, cpu, no_pers)?;
    // Every incarnation's output, in order.
    let incs = crate::durability::check::incarnations(&dir);
    let stdout: Vec<u8> = incs.iter().flat_map(|d| read(&d.join("stdout"))).collect();
    let stderr: Vec<u8> = incs.iter().flat_map(|d| read(&d.join("stderr"))).collect();
    Ok(RunResult {
        oc,
        stdout,
        stderr,
        dir,
    })
}

/// `patina verify`: `runs` runs of one seed into `out/run-K` (paths in `o` are absolute, so
/// `env` can change the working directory). The outcome is the runs' own when they agree,
/// else `nondeterministic` naming the first differing record.
pub fn verify(o: &Opts, out: &Path, runs: usize, vary: &[String]) -> Res<(Classified, ExitCode)> {
    let o = &o.clone();
    let out = std::path::absolute(out).unwrap_or_else(|_| out.to_path_buf());
    let cpus = cpu_choices();
    let all = allowed_cpus();
    let base_cpu = o.cfg.host_cpu.unwrap_or_else(default_cpu);
    // The `cpu` variant's runs start at a CPU chosen by process id (concurrent verifies spread).
    let cpu_off = std::process::id() as usize % cpus.len();
    let vary = |k: &str| vary.iter().any(|v| v == k);
    let mut reference: Option<RunResult> = None;
    let _load = if vary("load") {
        Some(Load::start())
    } else {
        None
    };
    let n = runs.max(1);
    let mut i = 0;
    while i < n {
        // `parallel`: up to 12 runs at once after the reference, each on its own core.
        // PATINA_PARALLEL lowers the batch (a shared host may cap concurrent sandboxes).
        let width: usize = std::env::var("PATINA_PARALLEL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(12)
            .max(2);
        let batch = if vary("parallel") && i > 0 {
            (n - i).min(width).min(all.len())
        } else {
            1
        };
        if vary("time") && i == 1 {
            let gap: u64 = std::env::var("PATINA_TIME_GAP_S")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600);
            println!("time: waiting {gap} s of wall time before run 1");
            std::thread::sleep(std::time::Duration::from_secs(gap));
        }
        if vary("sandbox") && i > 0 {
            churn();
        }
        let env_state = if vary("env") && i % 2 == 1 {
            Some(env_perturb())
        } else {
            None
        };
        let mut jobs = vec![];
        for j in 0..batch {
            let k = i + j;
            let cpu = if batch > 1 {
                all[(all.iter().position(|&c| c == base_cpu).unwrap_or(0) + 1 + j) % all.len()]
            } else if vary("cpu") {
                cpus[(k + cpu_off) % cpus.len()]
            } else {
                base_cpu
            };
            let no_pers = vary("aslr") && k % 2 == 1;
            jobs.push((k, cpu, no_pers, out.join(format!("run-{k}"))));
        }
        let results: Vec<(usize, usize, bool, Res<RunResult>)> = if batch == 1 {
            let (k, cpu, np, d) = jobs.pop().unwrap();
            vec![(k, cpu, np, one(o, d, cpu, np))]
        } else {
            std::thread::scope(|sc| {
                let hs: Vec<_> = jobs
                    .into_iter()
                    .map(|(k, cpu, np, d)| (k, cpu, np, sc.spawn(move || one(o, d, cpu, np))))
                    .collect();
                hs.into_iter()
                    .map(|(k, cpu, np, h)| {
                        (
                            k,
                            cpu,
                            np,
                            h.join().unwrap_or_else(|_| Err("run panicked".into())),
                        )
                    })
                    .collect()
            })
        };
        let env_changed = env_state.is_some();
        if let Some(st) = env_state {
            env_restore(st);
        }
        for (k, cpu, no_pers, res) in results {
            let rr = res?;
            println!(
                "run {k}: cpu {cpu} aslr {} load {} env {} {} {} switches {}",
                if no_pers { "on" } else { "off" },
                if vary("load") { "on" } else { "off" },
                if env_changed { "changed" } else { "base" },
                rr.oc.verdict.class,
                rr.oc.digest,
                rr.oc.switches
            );
            match &reference {
                None => reference = Some(rr),
                Some(r) => {
                    let same = r.oc.digest == rr.oc.digest
                        && r.oc.verdict == rr.oc.verdict
                        && r.oc.traps == rr.oc.traps
                        && r.oc.incarnations == rr.oc.incarnations
                        && r.oc.crashes == rr.oc.crashes
                        && r.stdout == rr.stdout
                        && r.stderr == rr.stderr;
                    if !same {
                        println!("divergence: run {k} differs from run 0");
                        let msg = match crate::log::first_run_difference(&r.dir, &rr.dir)? {
                            Some(d) => {
                                println!("{d}");
                                format!("run {k} differs from run 0: {d}")
                            }
                            None => {
                                println!("logs equal; outcome or output differ");
                                format!("run {k} differs from run 0 in its outcome or output")
                            }
                        };
                        let c = Classified::new(Outcome::Nondeterministic, "divergence", msg);
                        return Ok((c, ExitCode::from(Outcome::Nondeterministic.exit())));
                    }
                    // Long soaks: PATINA_VERIFY_PRUNE removes each run found identical
                    // to run 0 (run 0 stays for comparison).
                    if std::env::var_os("PATINA_VERIFY_PRUNE").is_some() {
                        let _ = std::fs::remove_dir_all(&rr.dir);
                    }
                }
            }
        }
        i += batch;
    }
    println!("identical: {n} runs in {}", out.display());
    let r = reference.ok_or("no runs")?;
    let c = crate::result::classified(&r.oc);
    let code = ExitCode::from(c.outcome.exit());
    Ok((c, code))
}
