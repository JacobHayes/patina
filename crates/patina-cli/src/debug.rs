//! `patina debug RUNDIR [--at EVENT] [--no-gdb]`: a replay of the run that stops the whole
//! simulated world just before one boundary event and lets the user's gdb attach to the
//! process about to act (ARCHITECTURE.md, "Debugging a run").
//!
//! The stop is the debug session's gate (`proto::ctl::DebugCtl`): whoever takes the event's
//! sequence number parks before it, with nothing recorded; every other thread is parked
//! already, waiting for the turn. The launcher's watch (`Watch`) sees the stop, finds the
//! process on the host, writes a gdb helper for it into `RUNDIR/debug` and starts gdb (or
//! prints how to attach); the gate opens when the debugger continues, detaches or exits. At
//! the end the replay's logs are compared with the run's, as `patina replay` compares them:
//! the session was the recorded run, or it left it at a record, which is named.

use crate::cli::{Args, Res};
use crate::outcome::Outcome;
use crate::Fail;
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering::*};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Wall seconds a debug session may last (its `--timeout`): as long as its user.
pub const NO_TIMEOUT: u64 = 100 * 86_400;
/// The replay's directory inside the run.
const DIR: &str = "debug";
/// The gdb helper: the stop's facts (`debug.json`) are read from beside it.
const HELPER: &str = include_str!("debug/patina-gdb.py");

/// What the launcher's watch needs of the session.
struct Session {
    /// The event about to happen, as the recorded run has it.
    event: String,
    gdb: Option<PathBuf>,
    /// Why there is no gdb to start (`--no-gdb`, none found, the host forbids attaching).
    no_gdb: String,
    /// load-time points: the runtime's own breakpoints and single steps share
    /// `SIGTRAP` with the debugger's, so gdb passes every `SIGTRAP` on and stepping is refused.
    sigtrap_pass: bool,
}

static SESSION: OnceLock<Session> = OnceLock::new();
/// The world stopped (the launcher's watch saw the gate taken).
static REACHED: AtomicBool = AtomicBool::new(false);

pub fn main(a: &Args) -> Result<ExitCode, Fail> {
    let err = |e: String| Fail(Outcome::Error, e);
    let [rundir] = a.positional.as_slice() else {
        return Err(err(
            "usage: patina debug RUNDIR [--at EVENT] [--no-gdb]".into()
        ));
    };
    let rundir = PathBuf::from(rundir);
    let (mut cfg, program) = crate::replay::load(&rundir).map_err(err)?;
    let recorded = crate::result::read_json(&rundir.join("result.json")).map_err(err)?;
    if crate::durability::check::boots(&rundir).is_empty() {
        return Err(err(format!(
            "{}: the run kept no logs (a sweep keeps those of the first runs of each finding): run the seed again with patina run to debug it",
            rundir.display()
        )));
    }
    // Spin points come of single steps and breakpoints the runtime takes with SIGTRAP, which
    // gdb would take as its own.
    if recorded["counters"]["sched"]["spin_yields"]
        .as_u64()
        .unwrap_or(0)
        != 0
    {
        return Err(err(format!(
            "{}: patina debug does not take a run whose threads yielded at spin points in this version",
            rundir.display()
        )));
    }
    // Absolute: the helper's paths must hold from any directory gdb is started in.
    let out = std::fs::canonicalize(&rundir)
        .map_err(|e| err(format!("{}: {e}", rundir.display())))?
        .join(DIR);
    // Written by this command only: a link there would put the replay elsewhere.
    if std::fs::symlink_metadata(&out).is_ok_and(|m| !m.is_dir()) {
        return Err(err(format!(
            "{}: not a directory this command made (remove it to debug the run)",
            out.display()
        )));
    }
    let events = recorded_events(&rundir).map_err(err)?;
    let (at, event) = resolve(&rundir, a.last("--at").unwrap_or("stop"), &events)?;
    let (gdb, no_gdb) = match (a.has("--no-gdb"), ptrace_refused(), find_gdb()) {
        (true, _, _) => (None, "--no-gdb".to_string()),
        (_, Some(why), _) => (None, why),
        (_, None, None) => (
            None,
            "no gdb found (PATH, PATINA_GDB); attach a debugger yourself".to_string(),
        ),
        (_, None, Some(g)) => (Some(g), String::new()),
    };
    let sigtrap_pass = cfg.preempt.points();
    let _ = SESSION.set(Session {
        event,
        gdb,
        no_gdb,
        sigtrap_pass,
    });
    cfg.debug_at = Some(at);
    let r = crate::replay::replay_into(&rundir, &out, cfg, program, &recorded)
        .map_err(|e| Fail(Outcome::Internal, e))?;
    let own = &r.own;
    println!("{} ({}): {}", own.outcome.name(), own.stop, own.message);
    let c = &r.classified;
    let left = match c.outcome {
        Outcome::Nondeterministic => first_left(&rundir, &out).map_err(err)?,
        _ => None,
    };
    let reached = REACHED.load(SeqCst);
    let did = notes(&out);
    let (code, left_at) = match left {
        None if c.outcome == Outcome::Nondeterministic || c.stop == "inputs-changed" => {
            println!("{}: {}", c.stop, c.message);
            (2, None)
        }
        None if !reached => {
            println!("the replay ended before seq {at}: there was no stop");
            (2, None)
        }
        None => {
            println!("identical: the session was the recorded run");
            (0, None)
        }
        Some((m, what)) => {
            println!(
                "the session left the recorded run at seq {m}{}: {what}; what the program did after it is another run",
                if did.is_empty() {
                    String::new()
                } else {
                    format!(" (the session {})", did.iter().map(|d| d.1).collect::<Vec<_>>().join(", "))
                }
            );
            (2, Some(m))
        }
    };
    // The same, for scripts: RUNDIR/debug/session.json.
    let facts = json!({
        "at": at,
        "stopped": reached,
        "identical": code == 0,
        "left_at": left_at,
        "did": did.iter().map(|d| d.0).collect::<Vec<_>>(),
    });
    std::fs::write(out.join("session.json"), format!("{facts}\n"))
        .map_err(|e| err(format!("{}: {e}", out.join("session.json").display())))?;
    Ok(ExitCode::from(code))
}

/// The recorded run's events (`log events`).
fn recorded_events(rundir: &Path) -> Res<Vec<Value>> {
    let sel = crate::events::Select::parse(None, 0, u64::MAX)?;
    let mut buf = vec![];
    crate::events::export(rundir, &sel, &mut buf)?;
    buf.split(|&c| c == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).map_err(|e| e.to_string()))
        .collect()
}

/// The sequence number `--at` names, and the event there in a few words.
fn resolve(rundir: &Path, at: &str, events: &[Value]) -> Result<(u64, String), Fail> {
    let err = |e: String| Fail(Outcome::Error, e);
    let seqd = |v: &&Value| v["seq"].as_u64().is_some();
    let pick = |all: Vec<&Value>, k: i64, what: &str| -> Result<u64, Fail> {
        if k == 0 {
            return Err(err(format!(
                "--at {at}: K counts from 1 (from the end when negative)"
            )));
        }
        let i = if k < 0 {
            all.len().checked_sub(k.unsigned_abs() as usize)
        } else {
            (k as usize).checked_sub(1)
        };
        i.and_then(|i| all.get(i))
            .and_then(|v| v["seq"].as_u64())
            .ok_or_else(|| err(format!("--at {at}: the run has {} {what}", all.len())))
    };
    // NAME[:MACHINE][:K]: the last part is K when it is a number.
    let split = |rest: &str| -> (String, Option<String>, i64) {
        let mut parts: Vec<&str> = rest.split(':').collect();
        let k = match parts.last().and_then(|p| p.parse::<i64>().ok()) {
            Some(k) if parts.len() > 1 => {
                parts.pop();
                k
            }
            _ => -1,
        };
        let machine = (parts.len() > 1).then(|| parts[1..].join(":"));
        (parts[0].to_string(), machine, k)
    };
    let seq = match at.split_once(':') {
        None if at == "stop" => match crate::explain::stop_event(rundir)? {
            Some(s) => s,
            None => {
                return Err(err(
                    "the run ended ok: explain names no event to stop at; give --at".into(),
                ))
            }
        },
        None if at == "end" => {
            let guest = |v: &&Value| {
                v["slot"].is_u64()
                    && matches!(
                        v["type"].as_str(),
                        Some("call" | "sdk" | "mark" | "sigfault" | "signal" | "insn" | "preempt")
                    )
            };
            pick(events.iter().filter(seqd).filter(guest).collect(), -1, "events")?
        }
        None if at == "crash" => pick(
            events.iter().filter(|v| v["type"] == "crash").collect(),
            -1,
            "crashes",
        )?,
        None => at.parse::<u64>().map_err(|_| {
            err(format!(
                "--at {at}: expected a sequence number, stop, end, crash, call:NAME, mark:LABEL, sdk:LABEL or fault:K"
            ))
        })?,
        Some(("fault", k)) => {
            let k = k
                .parse::<i64>()
                .map_err(|_| err(format!("--at {at}: fault:K takes a number")))?;
            pick(
                events.iter().filter(|v| v["type"] == "fault").collect(),
                k,
                "injected faults",
            )?
        }
        Some((kind @ ("call" | "mark" | "sdk"), rest)) => {
            let (name, machine, k) = split(rest);
            let key = if kind == "call" { "name" } else { "label" };
            let all = events
                .iter()
                .filter(|v| v["type"] == kind && v[key] == name.as_str())
                .filter(|v| machine.as_deref().is_none_or(|n| v["machine"] == n))
                .collect();
            pick(all, k, &format!("{kind} events named {name}"))?
        }
        Some(_) => return Err(err(format!("--at {at}: unknown form"))),
    };
    // The event of that number: a call (its file operations and a crash there share it).
    let at_seq = |v: &&Value| v["seq"].as_u64() == Some(seq);
    let ev = events
        .iter()
        .filter(at_seq)
        .find(|v| !matches!(v["type"].as_str(), Some("crash" | "op")))
        .or_else(|| events.iter().find(at_seq));
    let Some(ev) = ev else {
        let last = events.iter().filter_map(|v| v["seq"].as_u64()).max();
        return Err(err(format!(
            "--at {at}: no event {seq} in the run (its events end at {})",
            last.map_or("none".into(), |l| l.to_string())
        )));
    };
    let mut d = describe(ev);
    if ev["type"] != "crash" && events.iter().filter(at_seq).any(|v| v["type"] == "crash") {
        d.push_str("; the crash comes in it");
    }
    Ok((seq, d))
}

/// An event in a few words: its kind and name, and whose it is.
fn describe(v: &Value) -> String {
    let s = |k: &str| v[k].as_str().unwrap_or("");
    let what = match s("type") {
        "call" => format!("call {}", s("name")),
        "sdk" => format!("sdk {} {}", s("op"), s("label")),
        "mark" => format!("mark {}", s("label")),
        "sched" => format!("the supervisor's {}", s("op")),
        "fault" => format!("injected fault {}", s("class")),
        "op" => format!("{} on {}", s("op"), s("path")),
        "crash" => format!("{} crash", s("kind")),
        t => t.to_string(),
    };
    let mut who = vec![];
    if let Some(n) = v["machine"].as_str() {
        who.push(format!("machine {n}"));
    }
    let guest = !matches!(
        v["type"].as_str(),
        Some("sched" | "fault" | "crash" | "cut" | "net")
    );
    if let Some(slot) = v["slot"].as_u64().filter(|_| guest) {
        who.push(if slot == 0 {
            "main".into()
        } else {
            format!("t{slot}")
        });
    }
    match who.is_empty() {
        true => what,
        false => format!("{what} ({})", who.join(", ")),
    }
}

/// gdb from `PATINA_GDB`, else from `PATH`.
fn find_gdb() -> Option<PathBuf> {
    if let Some(g) = std::env::var_os("PATINA_GDB") {
        return Some(PathBuf::from(g));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("gdb"))
        .find(|p| p.is_file())
}

/// Why no debugger can attach to a guest on this host, if none can: Yama's ptrace scope 3
/// forbids every attach, and scope 2 every attach without `CAP_SYS_PTRACE`.
pub fn ptrace_refused() -> Option<String> {
    let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").ok()?;
    match scope.trim() {
        "3" => {
            Some("this host forbids every debugger attach (kernel.yama.ptrace_scope = 3)".into())
        }
        "2" if unsafe { libc::geteuid() } != 0 => {
            Some("this host lets only root attach a debugger (kernel.yama.ptrace_scope = 2)".into())
        }
        _ => None,
    }
}

/// What the helper saw the session do that leaves the recorded run (`notes`, one word a
/// line), in words.
fn notes(out: &Path) -> Vec<(&'static str, &'static str)> {
    let t = std::fs::read_to_string(out.join("notes")).unwrap_or_default();
    let mut said = vec![];
    for (k, w) in [
        ("memory", "wrote memory"),
        ("register", "wrote a register"),
        ("call", "called a function in the program"),
    ] {
        if t.lines().any(|l| l == k) {
            said.push((k, w));
        }
    }
    said
}

/// Where the replay first left the run: the recorded record's sequence number (the
/// replayed one's where the recorded log ended) and the difference in words.
fn first_left(rundir: &Path, out: &Path) -> Res<Option<(u64, String)>> {
    let (a, b) = (
        crate::durability::check::boots(rundir),
        crate::durability::check::boots(out),
    );
    for (da, db) in a.iter().zip(&b) {
        let load = |d: &Path| crate::log::load(&d.join("boundary.log").display().to_string());
        let (x, y) = (load(da)?, load(db)?);
        if let Some((_, ra, rb)) = crate::log::first_difference(&x, &y) {
            // Records are written when their event ends: the first that differs may follow
            // the event where the runs parted, whose number is the smaller.
            let seq = match (ra, rb) {
                (Some(a), Some(b)) => a.seq.min(b.seq),
                (a, b) => a.or(b).map_or(0, |r| r.seq),
            };
            let show = |r: Option<proto::Rec>| {
                r.map_or("(end of log)".into(), |r| crate::log::describe(&r))
            };
            return Ok(Some((
                seq,
                format!("recorded {}; replayed {}", show(ra), show(rb)),
            )));
        }
    }
    Ok(None)
}

/// The launcher's side of a debug session: waits for the stop, then hands the world to the
/// user's debugger and opens the gate when it lets go.
pub struct Watch {
    /// The run ended: no stop will come.
    ended: Arc<AtomicBool>,
    /// The launcher is ending the session (a SIGTERM): stop waiting for the debugger.
    quit: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watch {
    pub fn start(ctl: usize, keeper: i32, out: &Path) -> Watch {
        let (ended, quit) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let (e, q) = (ended.clone(), quit.clone());
        let out = out.to_path_buf();
        let thread = std::thread::spawn(move || {
            // SAFETY: the launcher keeps the control region mapped until `finish` returns.
            let c = unsafe { proto::Ctl::at(ctl as *mut u8) };
            while !e.load(Acquire) {
                let seq = c.debug.stopped.load(SeqCst);
                if seq != 0 {
                    REACHED.store(true, SeqCst);
                    c.debug.held.store(1, SeqCst);
                    if let Err(e) = stopped(c, ctl, keeper, &out, seq, &q) {
                        eprintln!("patina debug: {e}; the run goes on");
                    }
                    release(c);
                    c.debug.held.store(0, SeqCst);
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        Watch {
            ended,
            quit,
            thread: Some(thread),
        }
    }

    /// The run has ended: wait for the session (its debugger's exit) to end too, unless the
    /// launcher is ending it (`patient` false: a SIGTERM), which ends gdb.
    pub fn finish(mut self, patient: bool) {
        if !patient {
            self.quit.store(true, Release);
        }
        self.ended.store(true, Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn release(c: &proto::Ctl) {
    c.debug.go.store(1, SeqCst);
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            &c.debug.go as *const _ as usize,
            libc::FUTEX_WAKE,
            i32::MAX,
        )
    };
}

/// `SIGCONT` every guest process with a thread in the stopped state (`T`): a debugger that
/// exits without detaching can leave its stop in place. The runtime drops the signal.
fn wake_stopped(keeper: i32) {
    let Ok((_, procs)) = sandbox_procs(keeper) else {
        return;
    };
    for p in procs {
        let stopped = p.threads.iter().any(|t| {
            std::fs::read_to_string(format!("/proc/{}/task/{}/stat", p.host, t.1))
                .ok()
                .and_then(|s| s.rsplit_once(") ").map(|(_, r)| r.starts_with('T')))
                .unwrap_or(false)
        });
        if stopped {
            unsafe { libc::kill(p.host, libc::SIGCONT) };
        }
    }
}

/// A process of the sandbox as the host sees it.
struct Proc {
    pid: i32,
    host: i32,
    comm: String,
    /// The machine it runs on, in a run with machines.
    machine: String,
    /// (sandbox tid, host tid)
    threads: Vec<(i32, i32)>,
}

/// What gdb needs of process `host` and cannot find itself (the kernel's exe and auxv are
/// Patina's runtime, which loads the program): each ELF file it maps but the runtime, as
/// [its path, the file to read (through the process's root when the host's path is another
/// file), its load bias]; and with load-time points each trampoline, from the plans it
/// maps, as [start, end, the original instructions' address, their length, the offset of
/// their copy] in the process's addresses.
fn images(host: i32) -> Value {
    use std::os::unix::fs::MetadataExt;
    let maps = std::fs::read_to_string(format!("/proc/{host}/maps")).unwrap_or_default();
    let exe = std::fs::read_link(format!("/proc/{host}/exe")).unwrap_or_default();
    let (mut images, mut bias, mut plans) = (vec![], std::collections::HashMap::new(), vec![]);
    // Files done with: placed, or not ELF (a data file mapped many times is read once).
    let mut done = std::collections::HashSet::new();
    for line in maps.lines() {
        let w: Vec<&str> = line.splitn(6, ' ').collect();
        let path = w.get(5).map_or("", |p| p.trim_start());
        if !path.starts_with('/') || path.ends_with(" (deleted)") {
            continue;
        }
        if path.ends_with(".plan") {
            plans.push(path.to_string());
            continue;
        }
        let start = w[0]
            .split('-')
            .next()
            .and_then(|a| u64::from_str_radix(a, 16).ok());
        let off = w.get(2).and_then(|o| u64::from_str_radix(o, 16).ok());
        // The first mapping of the file where one of its segments starts gives its bias, not
        // only the one at offset 0: under load-time points a plan's page can stand there (a
        // small program whose text starts at file offset 0, as on arm64). Not an inaccessible
        // one: the loader's reservation between segments carries offsets of its own.
        if Path::new(path) == exe || done.contains(path) || w[1].starts_with("---") {
            continue;
        }
        let inside = format!("/proc/{host}/root{path}");
        let id = |p: &str| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
        let file = match id(path).is_some() && id(path) == id(&inside) {
            true => path.to_string(),
            false => inside,
        };
        let found = off.and_then(|off| {
            std::fs::read(&file)
                .ok()
                .map(|d| crate::rewrite::image_at(&d, off, w[1]))
        });
        match (found, start) {
            (Some(Ok((sha, Some(at)))), Some(start)) => {
                let b = start.wrapping_sub(at);
                bias.insert(sha, b);
                images.push(json!([path, file, b]));
                done.insert(path.to_string());
            }
            (Some(Err(_)) | None, _) => {
                done.insert(path.to_string());
            }
            _ => {}
        }
    }
    let mut tramps = vec![];
    for p in plans.iter().filter_map(|p| std::fs::read(p).ok()) {
        if let Ok((sha, ts)) = crate::rewrite::trampolines(&p) {
            let Some(&b) = bias.get(&sha) else { continue };
            tramps.extend(ts.iter().map(|t| {
                [
                    t[0].wrapping_add(b),
                    t[1].wrapping_add(b),
                    t[2].wrapping_add(b),
                    t[3],
                    t[4],
                ]
            }));
        }
    }
    tramps.sort();
    json!({"images": images, "tramps": tramps})
}

/// The innermost pid of a `/proc` status file's `NSpid` line.
fn ns_pid(status: &str) -> Option<i32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))?
        .split_whitespace()
        .last()?
        .parse()
        .ok()
}

/// The guest processes of the sandbox whose keeper is `keeper`: every process in the PID
/// namespace of the keeper's child that is PID 1 there, but PID 1 (the supervisor).
fn sandbox_procs(keeper: i32) -> Res<(String, Vec<Proc>)> {
    let kids = std::fs::read_to_string(format!("/proc/{keeper}/task/{keeper}/children"))
        .map_err(|e| format!("the sandbox's processes: {e}"))?;
    let pid1 = kids
        .split_whitespace()
        .filter_map(|p| p.parse::<i32>().ok())
        .find(|p| {
            std::fs::read_to_string(format!("/proc/{p}/status"))
                .is_ok_and(|s| ns_pid(&s) == Some(1))
        })
        .ok_or("the sandbox's PID 1 is gone")?;
    let ns = |p: i32| std::fs::read_link(format!("/proc/{p}/ns/pid")).ok();
    let mine = ns(pid1).ok_or("the sandbox's PID namespace cannot be read")?;
    let mut out = vec![];
    for d in std::fs::read_dir("/proc")
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let Some(host) = d.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if host == pid1 || ns(host).as_ref() != Some(&mine) {
            continue;
        }
        let Some(pid) = std::fs::read_to_string(format!("/proc/{host}/status"))
            .ok()
            .and_then(|s| ns_pid(&s))
        else {
            continue;
        };
        // The program names itself: shown, so nothing but printable characters.
        let comm: String = std::fs::read_to_string(format!("/proc/{host}/comm"))
            .unwrap_or_default()
            .trim()
            .chars()
            .map(|ch| if ch.is_control() { '?' } else { ch })
            .collect();
        let mut threads = vec![];
        for t in std::fs::read_dir(format!("/proc/{host}/task"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let Some(ht) = t.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            if let Some(st) = std::fs::read_to_string(format!("/proc/{host}/task/{ht}/status"))
                .ok()
                .and_then(|s| ns_pid(&s))
            {
                threads.push((st, ht));
            }
        }
        threads.sort_unstable();
        out.push(Proc {
            pid,
            host,
            comm,
            machine: String::new(),
            threads,
        });
    }
    out.sort_by_key(|p| p.pid);
    Ok((mine.display().to_string(), out))
}

/// The world is stopped before `seq`: say so, write the helper, and let the user's debugger
/// have it until it continues, detaches or exits.
fn stopped(
    c: &proto::Ctl,
    ctl: usize,
    keeper: i32,
    out: &Path,
    seq: u64,
    quit: &AtomicBool,
) -> Res<()> {
    let s = SESSION.get().ok_or("no debug session")?;
    let slot = c.debug.slot.load(SeqCst);
    let (pid, tid) = match slot.checked_sub(1) {
        Some(i) if (i as usize) < proto::ctl::MAX_THREADS => {
            // SAFETY: `ctl` is the base of the full control region.
            let sl = unsafe { &*proto::Ctl::at(ctl as *mut u8).slot(i as usize) };
            (sl.pid.load(SeqCst), sl.tid.load(SeqCst))
        }
        _ => (0, 0),
    };
    let (pidns, mut procs) = sandbox_procs(keeper)?;
    // With machines, each process's machine, from its threads' slots.
    // SAFETY: as above.
    let base = ctl as *mut u8;
    let tab = unsafe { proto::machine::MachineTab::at(base) };
    if tab.count() > 0 {
        for i in 0..proto::ctl::MAX_THREADS {
            let sl = unsafe { &*proto::Ctl::at(base).slot(i) };
            if sl.state.load(SeqCst) != proto::ctl::SLOT_LIVE {
                continue;
            }
            let (pid, k) = (sl.pid.load(SeqCst), sl.machine.load(SeqCst) as usize);
            if let Some(q) = procs.iter_mut().find(|q| q.pid == pid) {
                q.machine = String::from_utf8_lossy(tab.name(k)).into_owned();
            }
        }
    }
    let p = procs.iter().find(|p| p.pid == pid).ok_or(format!(
        "the process at the stop (pid {pid}) is not in the sandbox"
    ))?;
    let host_tid = p
        .threads
        .iter()
        .find(|t| t.0 == tid)
        .map_or(p.host, |t| t.1);
    let helper = out.join("patina-gdb.py");
    let release = out.join("release");
    let facts = json!({
        "seq": seq,
        "event": s.event,
        "pid": p.pid,
        "tid": tid,
        "host_pid": p.host,
        "host_tid": host_tid,
        "pidns": pidns,
        "sigtrap_pass": s.sigtrap_pass,
        "watchpoints": !(s.sigtrap_pass && cfg!(target_arch = "aarch64")),
        "release": release,
        "notes": out.join("notes"),
        "procs": procs.iter().map(|q| json!({"pid": q.pid, "host": q.host, "comm": q.comm, "machine": q.machine, "threads": q.threads.len(), "maps": images(q.host)})).collect::<Vec<_>>(),
    });
    crate::result::write_json(&out.join("debug.json"), &facts)?;
    // Whole or not there: a script may start gdb as soon as the helper exists.
    let tmp = out.join("patina-gdb.py.tmp");
    std::fs::write(
        &tmp,
        format!(
            "STOP = {:?}\n{HELPER}",
            out.join("debug.json").display().to_string()
        ),
    )
    .and_then(|_| std::fs::rename(&tmp, &helper))
    .map_err(|e| format!("{}: {e}", helper.display()))?;
    let others = procs
        .iter()
        .map(|q| q.threads.len())
        .sum::<usize>()
        .saturating_sub(1);
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "stopped before seq {seq}: {} (it has not run)", s.event);
    let whose = match c.debug.sup.load(SeqCst) {
        0 => "the turn",
        _ => "the supervisor's event; the last to ask it",
    };
    let _ = writeln!(
        o,
        "  {whose}: pid {} ({}{}) thread {tid} [host pid {}, thread {host_tid}]; other threads parked: {others}; processes: {}",
        p.pid,
        p.comm,
        if p.machine.is_empty() { String::new() } else { format!(", machine {}", p.machine) },
        p.host,
        procs.len()
    );
    let exact = match (s.sigtrap_pass, cfg!(target_arch = "aarch64")) {
        (true, false) => "reading (bt, print, x, info registers), breakpoints, watchpoints, continue, finish; no stepping in this run (its scheduling points share SIGTRAP with the debugger)",
        (true, true) => "reading (bt, print, x, info registers), breakpoints, continue, finish; no stepping or watchpoints in this run (its scheduling points share SIGTRAP with the debugger, and an arm64 watchpoint is stepped over)",
        (false, _) => "reading (bt, print, x, info registers), breakpoints, watchpoints, continue, step, next, stepi, finish",
    };
    let _ = writeln!(o, "  exact, the recorded run: {exact}");
    let _ = writeln!(
        o,
        "  another run from there: writing memory or registers, calling a function, a signal; the end names where the session left the run"
    );
    let interrupt = match s.sigtrap_pass {
        true => "Ctrl-C does not interrupt this run (set a breakpoint first)",
        false => "Ctrl-C stops this process at its next request to Patina",
    };
    let _ = writeln!(
        o,
        "  the world runs on when the debugger continues, detaches or quits; {interrupt}"
    );
    let attach = format!("gdb -x {}", helper.display());
    match &s.gdb {
        None => {
            let go = match unsafe { libc::isatty(0) } == 1 {
                true => "press Enter here when attached".to_string(),
                false => format!("then: touch {}", release.display()),
            };
            let _ = writeln!(
                o,
                "attach ({}): {attach}  (another debugger: host pid {}; {go})",
                s.no_gdb, p.host
            );
            drop(o);
            wait_release(&release, None, quit);
        }
        Some(g) => {
            let _ = writeln!(o, "gdb: {attach}");
            drop(o);
            run_gdb(c, keeper, g, &helper, &release, quit)?;
        }
    }
    Ok(())
}

/// Until the helper says the debugger let go (`release`), the debugger `gdb` exits, (no gdb)
/// Enter is pressed on a terminal, or the launcher ends the session (`quit`).
fn wait_release(release: &Path, mut gdb: Option<&mut std::process::Child>, quit: &AtomicBool) {
    let tty = unsafe { libc::isatty(0) } == 1;
    loop {
        if release.exists() || quit.load(Acquire) {
            return;
        }
        if let Some(g) = gdb.as_deref_mut() {
            if !matches!(g.try_wait(), Ok(None)) {
                return;
            }
        } else if tty && crate::sys::readable(0, 0) {
            let mut l = String::new();
            let _ = std::io::stdin().read_line(&mut l);
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// gdb in the foreground with the helper: in a process group of its own that holds the
/// terminal, so a Ctrl-C reaches gdb only (gdb passes it on as its interrupt), never the
/// launcher or the sandbox's keeper. The gate opens at its first continue (or detach, or
/// exit); then this waits for gdb to exit.
fn run_gdb(
    c: &proto::Ctl,
    keeper: i32,
    gdb: &Path,
    helper: &Path,
    release: &Path,
    quit: &AtomicBool,
) -> Res<()> {
    // The terminal is handed to gdb only when this process has it (not a background job).
    let tty = unsafe { libc::isatty(0) == 1 && libc::tcgetpgrp(0) == libc::getpgrp() };
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let saved_ok = tty && unsafe { libc::tcgetattr(0, &mut saved) } == 0;
    let mut cmd = std::process::Command::new(gdb);
    cmd.arg("-q").arg("-x").arg(helper);
    unsafe {
        cmd.pre_exec(move || {
            libc::setpgid(0, 0);
            // A Ctrl-Z would stop gdb's group, which no shell knows as a job: ignored, gdb
            // (readline) leaves it so.
            libc::signal(libc::SIGTSTP, libc::SIG_IGN);
            if tty {
                libc::signal(libc::SIGTTOU, libc::SIG_IGN);
                libc::tcsetpgrp(0, libc::getpid());
                libc::signal(libc::SIGTTOU, libc::SIG_DFL);
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("start {}: {e}", gdb.display()))?;
    wait_release(release, Some(&mut child), quit);
    self::release(c);
    // The run goes on; gdb stays until the user quits, unless the launcher is ending.
    while matches!(child.try_wait(), Ok(None)) {
        if quit.load(Acquire) {
            let _ = child.kill();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    c.debug.held.store(0, SeqCst);
    // A gdb that died with the processes stopped (its all-stop) leaves them stopped: go on.
    wake_stopped(keeper);
    if tty {
        unsafe {
            let old = libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            libc::tcsetpgrp(0, libc::getpgrp());
            if saved_ok {
                libc::tcsetattr(0, libc::TCSANOW, &saved);
            }
            libc::signal(libc::SIGTTOU, old);
        }
    }
    Ok(())
}
