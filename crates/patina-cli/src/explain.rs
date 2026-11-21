//! `patina explain RUNDIR`: the story of a run. The run is replayed once with observation on
//! (`Config::observe`: each data call's first bytes, its descriptor and its connection, kept in
//! `RUNDIR/explain/inc-K/observe.log`, outside the log and the digest); the replay must be the
//! run, record for record, as `patina replay` checks it, or nothing is told. The story is read
//! from the replay's event stream (`events::export`) and those observations: one line per
//! message between nodes or processes, output line, change to the work tree, fault, cut,
//! crash and node event, and with several threads on one machine one per turn; repeats fold,
//! and a window of the last lines is shown, ending with the event worth stopping at.
//!
//! Nothing here knows a program: lines are made of system calls, file operations, faults and
//! the scheduler's turns. Bytes from the program are escaped and cut before they are printed.

use crate::cli::{Args, Res};
use crate::outcome::Outcome;
use crate::Fail;
use proto::rec::{Rec, RecKind, OBS_DATA, OBS_HEAD, REC_SIZE, STR_BYTES, STR_CUT};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Story lines shown by default: the last ones.
const LAST: usize = 40;
/// Escaped payload characters shown on a line.
const SHOW: usize = 64;
/// The replay's directory inside the run, and the file that says it was checked.
const DIR: &str = "explain";
const CHECKED: &str = "explained.json";
/// The longest block of lines folding looks for, and the fewest repeats it folds.
const FOLD_SPAN: usize = 12;
const FOLD_MIN: usize = 3;
/// File types (`st_mode >> 12`) an observation names.
const S_FIFO: u64 = 1;
const S_REG: u64 = 8;
const S_CHR: u64 = 2;
const S_SOCK: u64 = 12;

pub fn main(a: &Args) -> Result<ExitCode, Fail> {
    let err = |e: String| Fail(Outcome::Error, e);
    let [rundir] = a.positional.as_slice() else {
        return Err(err(
            "usage: patina explain RUNDIR [--from SEQ] [--to SEQ] [--last N] [--grep TEXT] [--full]"
                .into(),
        ));
    };
    let rundir = PathBuf::from(rundir);
    let opts = View {
        from: a.num::<u64>("--from").map_err(err)?,
        to: a.num::<u64>("--to").map_err(err)?,
        last: a.num::<usize>("--last").map_err(err)?,
        grep: a.last("--grep").map(|g| {
            g.split('|')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        }),
        full: a.has("--full"),
    };
    let dir = observed(&rundir)?;
    let recorded = crate::result::read_json(&rundir.join("result.json")).map_err(err)?;
    let story = Story::read(&dir, &recorded).map_err(|e| Fail(Outcome::Internal, e))?;
    let out = std::io::stdout().lock();
    let r = if a.json() {
        story.json(&opts, &rundir, out)
    } else {
        story.text(&opts, &rundir, out)
    };
    match r {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(err(e.to_string())),
        _ => Ok(ExitCode::SUCCESS),
    }
}

/// The event the story stops at (`stop at:`): its sequence number, from the observed replay.
pub fn stop_event(rundir: &Path) -> Result<Option<u64>, Fail> {
    let dir = observed(rundir)?;
    let recorded = crate::result::read_json(&rundir.join("result.json"))
        .map_err(|e| Fail(Outcome::Error, e))?;
    let st = Story::read(&dir, &recorded).map_err(|e| Fail(Outcome::Internal, e))?;
    Ok(st.stop_at.map(|i| st.lines[i].seq))
}

/// The observed replay of `rundir`, made once and checked against the run: `RUNDIR/explain`.
fn observed(rundir: &Path) -> Result<PathBuf, Fail> {
    let err = |e: String| Fail(Outcome::Error, e);
    let (mut cfg, program) = crate::replay::load(rundir).map_err(err)?;
    let recorded = crate::result::read_json(&rundir.join("result.json")).map_err(err)?;
    let out = rundir.join(DIR);
    let checked = out.join(CHECKED);
    // Written by this command only: a link there would put the replay elsewhere.
    if std::fs::symlink_metadata(&out).is_ok_and(|m| !m.is_dir()) {
        return Err(err(format!(
            "{}: not a directory this command made (remove it to explain the run)",
            out.display()
        )));
    }
    // An earlier explain of this very run (its digest, in the marker and the replay's result):
    // read again, not replayed.
    let mine = crate::result::read_json(&out.join("result.json")).ok();
    if let (Ok(c), Some(m)) = (crate::result::read_json(&checked), mine) {
        if c["digest"] == recorded["digest"]
            && c["identical"] == true
            && m["digest"] == recorded["digest"]
        {
            return Ok(out);
        }
    }
    cfg.observe = true;
    let r = crate::replay::replay_into(rundir, &out, cfg, program, &recorded)
        .map_err(|e| Fail(Outcome::Internal, e))?;
    let c = &r.classified;
    if c.outcome == Outcome::Nondeterministic || c.stop == "inputs-changed" {
        return Err(Fail(
            c.outcome,
            format!(
                "the observed replay ({}) is not the run, so there is no story of it to tell: {}",
                out.display(),
                c.message
            ),
        ));
    }
    crate::result::write_json(
        &checked,
        &serde_json::json!({"identical": true, "digest": recorded["digest"]}),
    )
    .map_err(err)?;
    Ok(out)
}

/// What the user asked to see.
struct View {
    from: Option<u64>,
    to: Option<u64>,
    last: Option<usize>,
    grep: Option<Vec<String>>,
    full: bool,
}

/// One observation of a data call (`Rec::observed`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Obs {
    pub fd: u64,
    pub ftype: u64,
    pub conn: u64,
    pub raddr: u8,
    pub pid: i64,
    pub bytes: Vec<u8>,
    /// The call moved more than `bytes`.
    pub cut: bool,
}

/// An incarnation's observations by (sequence number, slot). A record that does not parse is
/// skipped: the file is the runtime's, written beside the program, and is never trusted.
pub fn read_observations(path: &Path) -> Res<HashMap<(u64, u16), Obs>> {
    use std::io::Read;
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut r = std::io::BufReader::new(f.take(proto::layout::LOG_MAX));
    let mut b = [0u8; REC_SIZE];
    let recs = std::iter::from_fn(|| r.read_exact(&mut b).ok().map(|()| b));
    Ok(parse_observations(recs))
}

/// At most this many observations are read of an incarnation (a story needs far fewer).
const OBS_MAX: usize = 1 << 20;

pub fn parse_observations(
    recs: impl IntoIterator<Item = [u8; REC_SIZE]>,
) -> HashMap<(u64, u16), Obs> {
    let mut m = HashMap::new();
    let mut cur: Option<((u64, u16), Obs, usize)> = None;
    for c in recs {
        if m.len() >= OBS_MAX {
            break;
        }
        let r = Rec::from_bytes(&c);
        if r.kind != RecKind::Observe as u8 {
            continue;
        }
        if r.class & !STR_CUT == OBS_HEAD {
            if let Some((k, o, _)) = cur.take() {
                m.insert(k, o);
            }
            let o = Obs {
                fd: r.args[0],
                ftype: r.args[1],
                conn: r.args[2],
                raddr: r.args[4] as u8,
                pid: r.ret,
                bytes: vec![],
                cut: r.class & STR_CUT != 0,
            };
            let want = (r.nr as usize).min(proto::rec::OBS_BYTES);
            cur = Some(((r.seq, r.slot), o, want));
        } else if r.class == OBS_DATA {
            if let Some(((seq, slot), o, want)) = cur.as_mut() {
                if r.seq == *seq && r.slot == *slot && o.bytes.len() < *want {
                    let k = (*want - o.bytes.len()).min(STR_BYTES);
                    o.bytes.extend_from_slice(&r.str_bytes()[..k]);
                }
            }
        }
    }
    if let Some((k, o, _)) = cur {
        m.insert(k, o);
    }
    m
}

/// A disk line takes more operations until it is this long.
const DISK_LINE: usize = 400;

/// A line of the story as a terminal shows it: names and labels come from the program, so a
/// control or direction-changing character is escaped (`\u{..}`), never sent.
fn clean(s: &str) -> std::borrow::Cow<'_, str> {
    let bad = |c: char| {
        c.is_control()
            || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    };
    if !s.chars().any(bad) {
        return s.into();
    }
    s.chars()
        .map(|c| match bad(c) {
            true => format!("\\u{{{:x}}}", c as u32),
            false => c.to_string(),
        })
        .collect::<String>()
        .into()
}

/// Bytes from the program on one line: printable ASCII as it is, everything else escaped
/// (`\n`, `\t`, `\r`, `\"`, `\\`, `\xNN`), at most `SHOW` characters, `...` when cut here or by the observation.
pub fn quote(b: &[u8], more: bool) -> String {
    let mut s = String::new();
    let mut cut = more;
    for &c in b {
        let e = match c {
            b'"' => "\\\"".to_string(),
            b'\\' => "\\\\".to_string(),
            b'\n' => "\\n".to_string(),
            b'\t' => "\\t".to_string(),
            b'\r' => "\\r".to_string(),
            0x20..=0x7e => (c as char).to_string(),
            _ => format!("\\x{c:02x}"),
        };
        if s.len() + e.len() > SHOW {
            cut = true;
            break;
        }
        s.push_str(&e);
    }
    format!("\"{s}\"{}", if cut { "..." } else { "" })
}

/// A story line. `who` is the actor (a node, or a thread on one machine; empty for the
/// network and the seed's own events).
#[derive(Clone, Debug)]
struct Line {
    seq: u64,
    t: u64,
    who: String,
    kind: &'static str,
    text: String,
    /// A turn in which nothing notable happened: left out of a story longer than its window.
    quiet: bool,
}

impl Line {
    /// The receiver of a message line (`-> PEER ...`), when known.
    fn to(&self) -> Option<&str> {
        let peer = self.text.strip_prefix("-> ")?.split(' ').next()?;
        (self.kind == "msg" && !matches!(peer, "?" | "conn")).then_some(peer)
    }

    /// What folding compares: the line with its numbers taken out.
    fn key(&self) -> String {
        let mut k = format!("{}\u{1}{}\u{1}", self.who, self.kind);
        let mut digit = false;
        for c in self.text.chars() {
            if c.is_ascii_digit() {
                if !digit {
                    k.push('N');
                }
                digit = true;
            } else {
                k.push(c);
                digit = false;
            }
        }
        k
    }
    /// Lines a window keeps whatever `--grep` says: what the seed did, and how actors ended.
    fn context(&self) -> bool {
        matches!(
            self.kind,
            "fault" | "network" | "crash" | "node" | "exits" | "prints" | "signal"
        )
    }
}

/// Per file of a work tree: writes since its last fsync, writes, fsyncs.
#[derive(Default, Clone, Copy)]
struct Synced {
    since: u64,
    writes: u64,
    fsyncs: u64,
}

/// The turn on one machine: one thread running until it waits, yields or ends.
struct Turn {
    slot: u16,
    /// Its line in `lines`, filled in when it ends.
    line: usize,
    calls: u64,
    preempts: u64,
    /// Threads and processes it started, threads it woke.
    threads: u64,
    procs: u64,
    woken: u64,
    end: Option<&'static str>,
}

struct Story {
    outcome: String,
    seed: u64,
    events: u64,
    nodes: Vec<String>,
    lines: Vec<Line>,
    t0: Option<u64>,
    /// Whether the run had preemptions in computation (`--preempt points`, `branches`, compute
    /// points), and whether any line is an exchange between actors.
    preempts: u64,
    stop_at: Option<usize>,
}

/// Reads the event stream into story lines.
struct Reader<'a> {
    obs: Vec<HashMap<(u64, u16), Obs>>,
    nodes: Vec<String>,
    /// Thread slots seen on one machine: more than one makes turns.
    threads: bool,
    turn: Option<Turn>,
    /// Thread slots that had a turn.
    slots: std::collections::BTreeSet<u16>,
    files: HashMap<(String, String), Synced>,
    /// On one machine, the process of each thread slot (its last `Hello`).
    pids: HashMap<u16, u64>,
    /// A write to a pipe or a local socket waiting for the read of the same bytes (its hash).
    pipes: HashMap<String, usize>,
    /// The disk line being extended and the first operation in it.
    disk: Option<(usize, String)>,
    /// On one machine, who used each connection (incarnation, id) and when (an event count),
    /// and the sends whose receiver is told once the whole run is read.
    ends: HashMap<(usize, u64), Vec<(u64, String)>>,
    sends: Vec<(usize, (usize, u64), u64, String)>,
    st: &'a mut Story,
    events: u64,
}

impl Story {
    fn read(dir: &Path, recorded: &Value) -> Res<Story> {
        let incs = crate::durability::check::incarnations(dir);
        let obs = incs
            .iter()
            .map(|i| read_observations(&i.join(crate::log::OBSERVE_LOG)))
            .collect::<Res<Vec<_>>>()?;
        let mut st = Story {
            outcome: format!(
                "{} ({}): {}",
                recorded["outcome"].as_str().unwrap_or("?"),
                recorded["stop"].as_str().unwrap_or("?"),
                recorded["message"].as_str().unwrap_or("")
            ),
            seed: recorded["seed"].as_u64().unwrap_or(0),
            events: 0,
            nodes: vec![],
            lines: vec![],
            t0: None,
            preempts: 0,
            stop_at: None,
        };
        let mut rd = Reader {
            obs,
            nodes: vec![],
            // Turns are told on one machine (the header of a run with nodes turns them off:
            // there the machines and their messages are; a node's threads are its own).
            threads: true,
            turn: None,
            slots: Default::default(),
            files: HashMap::new(),
            pids: HashMap::new(),
            pipes: HashMap::new(),
            disk: None,
            ends: HashMap::new(),
            sends: vec![],
            st: &mut st,
            events: 0,
        };
        let sel = crate::events::Select::parse(None, 0, u64::MAX)?;
        let mut feed = Feed {
            buf: vec![],
            f: |l: &[u8]| -> Res<()> {
                let v: Value = serde_json::from_slice(l).map_err(|e| e.to_string())?;
                rd.event(&v);
                Ok(())
            },
            err: None,
        };
        crate::events::export(dir, &sel, &mut feed)?;
        feed.finish()?;
        drop(feed);
        rd.end_turn();
        rd.receivers();
        if rd.slots.len() <= 1 {
            st_lines_retain(rd.st);
        }
        let events = rd.events;
        let nodes = rd.nodes.clone();
        drop(rd);
        st.events = events;
        st.nodes = nodes;
        st.stop_at = st.stop_line(recorded);
        Ok(st)
    }

    /// The line worth stopping at: for a failed assertion the assertion; otherwise in the
    /// actor that failed, the last message that reached it before its failure's output, or
    /// that output, or its end.
    fn stop_line(&self, r: &Value) -> Option<usize> {
        let ls = &self.lines;
        if r["outcome"] == "ok" {
            return None;
        }
        if r["outcome"] == "violation" {
            let label = r["message"].as_str()?.split(':').next()?.trim().to_string();
            return ls.iter().rposition(|l| {
                l.kind == "sdk" && l.text.starts_with("assert ") && l.text[7..] == label
            });
        }
        // The actor that ended the run: a node that failed, or the last that exited, crashed
        // or took a fatal signal.
        let failed = r["node_end"]["node"].as_str().map(str::to_string);
        let end = match &failed {
            Some(n) => ls.iter().rposition(|l| &l.who == n)?,
            None => ls
                .iter()
                .rposition(|l| matches!(l.kind, "exits" | "signal"))
                .or_else(|| ls.len().checked_sub(1))?,
        };
        let who = ls[end].who.clone();
        // Its output just before its end: the failure's message.
        let mut first_out = None;
        for i in (0..end).rev() {
            let l = &ls[i];
            if l.who != who {
                continue;
            }
            if l.kind == "prints" {
                first_out = Some(i);
            } else if l.kind != "turn" {
                break;
            }
        }
        let before = first_out.unwrap_or(end);
        // The last thing that reached it before that: a message into it, a call of its that
        // failed, a fault on it.
        let into = format!("-> {who} ");
        let cause = (0..before).rev().find(|&i| {
            let l = &ls[i];
            (l.kind == "msg" && l.who != who && l.text.starts_with(&into))
                || (matches!(l.kind, "error" | "fault") && l.who == who)
        });
        Some(cause.or(first_out).unwrap_or(end))
    }

    /// The view's selection of the lines, folded (`--full`: all, none folded), and how many
    /// lines that is before the window takes its last ones.
    fn selected(&self, v: &View) -> (Vec<Line>, usize) {
        let base = if v.full {
            self.lines.clone()
        } else {
            self.told()
        };
        let picked: Vec<Line> = base
            .into_iter()
            .filter(|l| v.from.is_none_or(|f| l.seq >= f) && v.to.is_none_or(|t| l.seq <= t))
            .filter(|l| match &v.grep {
                None => true,
                Some(g) => {
                    l.context()
                        || g.iter()
                            .any(|p| l.who.contains(p.as_str()) || l.text.contains(p.as_str()))
                }
            })
            .collect();
        let mut sel = if v.full { picked } else { fold(&picked) };
        let n = sel.len();
        let window = v.from.is_some() || v.to.is_some() || v.full;
        let last = v.last.unwrap_or(if window { usize::MAX } else { LAST });
        if sel.len() > last {
            sel.drain(..sel.len() - last);
        }
        (sel, n)
    }

    /// The lines told without `--full`: a story longer than its window leaves out its quiet
    /// turns (each thread's turns that only made calls).
    fn told(&self) -> Vec<Line> {
        let long = self.lines.len() > LAST;
        self.lines
            .iter()
            .filter(|l| !(long && l.quiet))
            .cloned()
            .collect()
    }

    fn quiet_turns(&self) -> usize {
        if self.lines.len() > LAST {
            self.lines.iter().filter(|l| l.quiet).count()
        } else {
            0
        }
    }

    /// Whether the story has any exchange between actors or anything the seed did.
    fn exchanges(&self) -> bool {
        self.lines.iter().any(|l| {
            matches!(
                l.kind,
                "msg" | "disk" | "fault" | "network" | "crash" | "node" | "unsynced"
            )
        })
    }

    fn off(&self, t: u64) -> f64 {
        t.saturating_sub(self.t0.unwrap_or(0)) as f64 / 1e6
    }

    /// Lines a window does not show that the window's lines depend on: what the seed did
    /// before it (faults, cuts, crashes, node events), folded by kind.
    fn before(&self, first: u64) -> Vec<Line> {
        // The last of each kind of line, its numbers aside, with how many there were.
        // By key: the last line, how many, the first's number, and when it was last seen.
        let mut by: HashMap<String, (Line, usize, u64, usize)> = HashMap::new();
        for (i, l) in self.lines.iter().enumerate() {
            if l.seq >= first
                || !matches!(l.kind, "fault" | "network" | "crash" | "node" | "unsynced")
            {
                continue;
            }
            let e = by
                .entry(l.key())
                .or_insert_with(|| (l.clone(), 0, l.seq, i));
            *e = (l.clone(), e.1 + 1, e.2, i);
        }
        let mut out: Vec<(Line, usize, u64, usize)> = by.into_values().collect();
        out.sort_by_key(|o| o.3);
        let n = out.len();
        out.drain(..n.saturating_sub(8));
        out.into_iter()
            .map(|(l, n, first, _)| (l, n, first))
            .map(|(mut l, n, first)| {
                if n > 1 {
                    l.text += &format!(" ({n} times, the first at {first})");
                }
                l
            })
            .collect()
    }

    fn text(&self, v: &View, rundir: &Path, mut w: impl Write) -> std::io::Result<()> {
        let (sel, n) = self.selected(v);
        writeln!(w, "{}", clean(&self.outcome))?;
        let quiet = match self.quiet_turns() {
            q if q > 0 && !v.full => format!(" ({q} quiet turns left out)"),
            _ => String::new(),
        };
        let what = if v.grep.is_some() { " with --grep" } else { "" };
        let shown = if sel.len() == n {
            format!("showing all {n}{what}")
        } else {
            format!(
                "showing the last {} of {n}{what} (--last N, --from/--to SEQ, --grep TEXT, --full for others)",
                sel.len()
            )
        };
        writeln!(
            w,
            "seed {}: {} events, {} story lines{quiet}; {shown}",
            self.seed,
            self.events,
            self.lines.len(),
        )?;
        writeln!(
            w,
            "data: the first {} bytes of each read, write, send and receive, from a replay identical to the run ({})",
            proto::rec::OBS_BYTES,
            rundir.join(DIR).display()
        )?;
        let quiet = !self.exchanges() && self.preempts > 0 && !v.full && self.stop_at.is_some();
        if quiet {
            writeln!(
                w,
                "note: no thread exchanged anything through the log before the failure (no message, file change, fault or cut), \
                 and the run was preempted {} times in computation: a race between system calls, in the program's own memory, \
                 is not in the log, so this story cannot show its cause. `patina log events {} --types preempt,call` lists \
                 where the threads switched.",
                self.preempts,
                rundir.display()
            )?;
        }
        let first = sel.first().map_or(u64::MAX, |l| l.seq);
        let before = self.before(first);
        if !before.is_empty() {
            writeln!(w, "before this window:")?;
            self.print(&mut w, &before)?;
        }
        writeln!(w)?;
        let sel = if quiet {
            // How it ended, without the turns: they are noise here (and so is a fold of them).
            let ends: Vec<Line> = sel
                .into_iter()
                .filter(|l| l.kind != "turn" && l.kind != "fold")
                .collect();
            let n = ends.len();
            ends.into_iter().skip(n.saturating_sub(6)).collect()
        } else {
            sel
        };
        self.print(&mut w, &sel)?;
        if let Some(i) = self.stop_at {
            let l = &self.lines[i];
            writeln!(
                w,
                "stop at: event {} ({}{}{}); its record: patina log events {} --from {} --to {}",
                l.seq,
                clean(&l.who),
                if l.who.is_empty() { "" } else { " " },
                clean(&l.text),
                rundir.display(),
                l.seq,
                l.seq
            )?;
        }
        Ok(())
    }

    fn print(&self, w: &mut impl Write, ls: &[Line]) -> std::io::Result<()> {
        let width = ls.iter().map(|l| l.who.len()).max().unwrap_or(0).max(4);
        for l in ls {
            writeln!(
                w,
                "{:>8}  +{:>11.3} ms  {:<width$}  {}",
                l.seq,
                self.off(l.t),
                clean(&l.who),
                clean(&l.text)
            )?;
        }
        Ok(())
    }

    fn json(&self, v: &View, _rundir: &Path, mut w: impl Write) -> std::io::Result<()> {
        let (sel, _) = self.selected(v);
        let line = |kind: &str, seq: Option<u64>, t: Option<u64>, who: &str, text: &str| {
            let mut o = serde_json::json!({"kind": kind, "who": who, "text": text});
            if let Some(s) = seq {
                o["seq"] = s.into();
            }
            if let Some(t) = t {
                o["t"] = t.into();
            }
            o
        };
        writeln!(w, "{}", line("outcome", None, None, "", &self.outcome))?;
        // The context before the window first, as in the text.
        let before = self.before(sel.first().map_or(u64::MAX, |l| l.seq));
        for l in before.iter().chain(&sel) {
            let mut o = line(l.kind, Some(l.seq), Some(l.t), &l.who, &l.text);
            // A message's receiver, when the story knows it.
            if let Some(to) = l.to() {
                o["to"] = to.into();
            }
            writeln!(w, "{o}")?;
        }
        if let Some(i) = self.stop_at {
            let l = &self.lines[i];
            let mut o = line("stop", Some(l.seq), Some(l.t), &l.who, &l.text);
            if let Some(to) = l.to() {
                o["to"] = to.into();
            }
            writeln!(w, "{o}")?;
        }
        Ok(())
    }
}

/// One thread on one machine: its turns tell nothing.
fn st_lines_retain(st: &mut Story) {
    st.lines.retain(|l| l.kind != "turn");
}

/// Fold blocks of lines that repeat (their numbers aside) three times or more into the first
/// block and one line that says how many times it came.
fn fold(ls: &[Line]) -> Vec<Line> {
    let keys: Vec<String> = ls.iter().map(Line::key).collect();
    let mut out = vec![];
    let mut i = 0;
    while i < ls.len() {
        let mut best: Option<(usize, usize)> = None;
        for p in 1..=FOLD_SPAN {
            if i + p > ls.len() {
                break;
            }
            let mut n = 1;
            while i + (n + 1) * p <= ls.len() && keys[i + n * p..i + (n + 1) * p] == keys[i..i + p]
            {
                n += 1;
            }
            if n >= FOLD_MIN && best.is_none_or(|(bn, bp)| n * p > bn * bp) {
                best = Some((n, p));
            }
        }
        match best {
            Some((n, p)) => {
                out.extend_from_slice(&ls[i..i + p]);
                let last = &ls[i + n * p - 1];
                out.push(Line {
                    seq: last.seq,
                    t: last.t,
                    who: String::new(),
                    quiet: false,
                    kind: "fold",
                    text: format!(
                        "... the {} above, {n} times in all, until here",
                        if p == 1 {
                            "line".to_string()
                        } else {
                            format!("{p} lines")
                        }
                    ),
                });
                i += n * p;
            }
            None => {
                out.push(ls[i].clone());
                i += 1;
            }
        }
    }
    out
}

/// A `Write` that hands each complete line to `f`.
struct Feed<F: FnMut(&[u8]) -> Res<()>> {
    buf: Vec<u8>,
    f: F,
    err: Option<String>,
}

impl<F: FnMut(&[u8]) -> Res<()>> Feed<F> {
    fn finish(&mut self) -> Res<()> {
        if let Some(e) = self.err.take() {
            return Err(e);
        }
        if !self.buf.is_empty() {
            let b = std::mem::take(&mut self.buf);
            (self.f)(&b)?;
        }
        Ok(())
    }
}

impl<F: FnMut(&[u8]) -> Res<()>> Write for Feed<F> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        let mut start = 0;
        while let Some(n) = self.buf[start..].iter().position(|&c| c == b'\n') {
            if self.err.is_none() {
                if let Err(e) = (self.f)(&self.buf[start..start + n]) {
                    self.err = Some(e);
                }
            }
            start += n + 1;
        }
        self.buf.drain(..start);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn s<'v>(v: &'v Value, k: &str) -> &'v str {
    v[k].as_str().unwrap_or("")
}

fn u(v: &Value, k: &str) -> u64 {
    v[k].as_u64().unwrap_or(0)
}

/// A file's name as a story says it: its path.
fn path(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("(no name)").to_string()
}

fn set(v: &Value) -> String {
    let names: Vec<&str> = v
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    format!("{{{}}}", names.join(","))
}

impl Reader<'_> {
    fn who(&self, v: &Value) -> String {
        if !self.nodes.is_empty() {
            return v["node"].as_str().unwrap_or("").to_string();
        }
        let Some(n) = v["slot"].as_u64() else {
            return String::new();
        };
        let name = match n {
            0 => "main".to_string(),
            n => format!("t{n}"),
        };
        // A thread of another process than the first names its process.
        match (self.pids.get(&(n as u16)), self.pids.get(&0)) {
            (Some(p), Some(first)) if p != first => format!("{name}/p{p}"),
            _ => name,
        }
    }

    fn push(&mut self, v: &Value, who: String, kind: &'static str, text: String) -> usize {
        if kind != "disk" {
            self.disk = None;
        }
        let seq = v["seq"].as_u64().unwrap_or(0);
        let t = v["t"].as_u64().unwrap_or(0);
        self.st.lines.push(Line {
            seq,
            t,
            who,
            kind,
            text,
            quiet: false,
        });
        self.st.lines.len() - 1
    }

    /// On one machine, each send's receiver: the first other thread that used its connection
    /// after it, or any other that did.
    fn receivers(&mut self) {
        for (i, c, at, q) in std::mem::take(&mut self.sends) {
            let me = self.st.lines[i].who.clone();
            let Some(ends) = self.ends.get(&c) else {
                continue;
            };
            // Only itself on it: a connection a thread holds both ends of.
            let peer = ends
                .iter()
                .find(|(o, w)| *o > at && *w != me)
                .or_else(|| ends.iter().find(|(_, w)| *w != me))
                .map_or(me.as_str(), |(_, p)| p.as_str());
            self.st.lines[i].text = format!("-> {peer} {q}");
        }
    }

    /// A turn ends (at the next thread's event, or at the end).
    fn end_turn(&mut self) {
        let Some(t) = self.turn.take() else {
            return;
        };
        let notes = t.threads + t.procs + t.woken;
        // A turn in which nothing ran (a thread woken only to wait again) tells nothing.
        if t.calls == 0 && t.preempts == 0 && notes == 0 && t.line + 1 == self.st.lines.len() {
            self.st.lines.pop();
            return;
        }
        let mut text = format!("{} call{}", t.calls, if t.calls == 1 { "" } else { "s" });
        if t.preempts > 0 {
            text += &format!(
                ", {} preemption{} in computation",
                t.preempts,
                if t.preempts == 1 { "" } else { "s" }
            );
        }
        let n = |k: u64, one: &str, many: &str| match k {
            0 => String::new(),
            1 => format!(", {one}"),
            k => format!(", {}", many.replace('N', &k.to_string())),
        };
        text += &n(t.threads, "starts a thread", "starts N threads");
        text += &n(t.procs, "starts a process", "starts N processes");
        text += &n(t.woken, "wakes a waiting thread", "wakes N waiting threads");
        if let Some(e) = t.end {
            text += "; then ";
            text += e;
        }
        // Quiet: nothing in it but calls and wakes, and the thread goes on after it.
        let last = t.line + 1 == self.st.lines.len();
        let ends = matches!(t.end, Some("ends" | "its process ends"));
        self.st.lines[t.line].quiet = t.threads + t.procs == 0 && last && !ends;
        self.st.lines[t.line].text = text;
    }

    /// Turns on one machine: a thread's event after another's starts its turn.
    fn turn(&mut self, v: &Value) {
        if !self.threads {
            return;
        }
        let Some(slot) = v["slot"].as_u64().map(|s| s as u16) else {
            return;
        };
        if self.turn.as_ref().is_some_and(|t| t.slot == slot) {
            return;
        }
        self.end_turn();
        self.slots.insert(slot);
        let who = self.who(v);
        let line = self.push(v, who, "turn", String::new());
        self.turn = Some(Turn {
            slot,
            line,
            calls: 0,
            preempts: 0,
            threads: 0,
            procs: 0,
            woken: 0,
            end: None,
        });
    }

    fn event(&mut self, v: &Value) {
        self.events += 1;
        let ty = s(v, "type");
        if let Some(t) = v["t"].as_u64() {
            if self.st.t0.is_none() {
                self.st.t0 = Some(t);
            }
        }
        match ty {
            "header" => {
                self.nodes = v["nodes"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if !self.nodes.is_empty() {
                    self.threads = false;
                }
            }
            "inc" if u(v, "inc") > 0 => {
                self.end_turn();
                self.disk = None;
                let l = Line {
                    seq: self.st.lines.last().map_or(0, |l| l.seq),
                    t: self.st.lines.last().map_or(0, |l| l.t),
                    who: String::new(),
                    kind: "crash",
                    text: format!("the machine starts again (incarnation {})", u(v, "inc")),
                    quiet: false,
                };
                self.st.lines.push(l);
            }
            "call" => self.call(v),
            "op" => self.op(v),
            "fault" => {
                self.turn(v);
                let class = s(v, "class");
                // Shown by their own events (`net`, `crash`, `node`), or one per message.
                if matches!(
                    class,
                    "partition" | "crash" | "net-delay" | "net-chunk" | "kill" | "pause" | "clock"
                ) {
                    return;
                }
                let mut d = vec![];
                for k in [
                    "call", "object", "errno", "count", "bytes", "delay_ns", "swap", "target",
                ] {
                    if !v[k].is_null() {
                        d.push(format!(
                            "{k} {}",
                            v[k].as_str().map_or(v[k].to_string(), str::to_string)
                        ));
                    }
                }
                if let Some(l) = v["link"].as_array() {
                    let l: Vec<&str> = l.iter().filter_map(|x| x.as_str()).collect();
                    d.push(format!("link {}", l.join("-")));
                }
                let who = if v["link"].is_null() {
                    self.who(v)
                } else {
                    String::new()
                };
                self.push(v, who, "fault", format!("FAULT {class}: {}", d.join(", ")));
            }
            "crash" => {
                self.end_turn();
                let node = v["node"].as_str().unwrap_or("").to_string();
                // Unsynced writes are what a machine crash may lose; a process crash leaves
                // them in the page cache, still unsynced.
                let machine = s(v, "kind") == "machine";
                let mut files: Vec<(String, Synced)> = self
                    .files
                    .iter()
                    .filter(|((n, _), f)| machine && *n == node && f.since > 0)
                    .map(|((_, p), f)| (p.clone(), *f))
                    .collect();
                files.sort_by(|a, b| a.0.cmp(&b.0));
                let who = node.clone();
                for (p, f) in files {
                    self.push(
                        v,
                        who.clone(),
                        "unsynced",
                        format!(
                            "at the crash {p} had {} write{} not followed by an fsync ({} writes, {} fsyncs in all)",
                            f.since,
                            if f.since == 1 { "" } else { "s" },
                            f.writes,
                            f.fsyncs
                        ),
                    );
                }
                if machine {
                    self.files.retain(|(n, _), _| *n != node);
                }
                let lost = &v["lost"];
                let mut what = vec![];
                for (k, word) in [
                    ("changed", "changed"),
                    ("missing", "missing"),
                    ("back", "back"),
                ] {
                    if u(lost, k) > 0 {
                        what.push(format!("{} {word}", u(lost, k)));
                    }
                }
                let paths: Vec<&str> = lost["paths"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                let lost = if lost.is_null() {
                    String::new()
                } else if what.is_empty() {
                    "; lost nothing".to_string()
                } else {
                    format!("; lost: {} ({})", what.join(", "), paths.join(", "))
                };
                let point = match v["point"].as_u64() {
                    Some(p) => format!(" at crash point {p}"),
                    None => String::new(),
                };
                self.push(
                    v,
                    who,
                    "crash",
                    format!("CRASH {}{point}{lost}", s(v, "kind")),
                );
            }
            "net" => match (s(v, "event"), s(v, "by")) {
                ("cut", "seed") => {
                    self.push(
                        v,
                        String::new(),
                        "network",
                        format!(
                            "NETWORK partition {}: {} cut {} | {} for {} ms",
                            u(v, "n"),
                            s(v, "shape"),
                            set(&v["a"]),
                            set(&v["b"]),
                            u(v, "length_ms")
                        ),
                    );
                }
                ("heal", "seed") => {
                    self.push(
                        v,
                        String::new(),
                        "network",
                        format!("NETWORK partition {} healed", u(v, "n")),
                    );
                }
                ("cut", _) => {
                    let arrow = if v["both"] == true { "<->" } else { "->" };
                    self.push(
                        v,
                        "driver".into(),
                        "network",
                        format!("NETWORK cut {} {arrow} {}", set(&v["from"]), set(&v["to"])),
                    );
                }
                ("heal", _) => {
                    self.push(v, "driver".into(), "network", "NETWORK heal".into());
                }
                _ => {}
            },
            "node" => {
                let name = s(v, "name").to_string();
                let text = match s(v, "event") {
                    "start" if u(v, "incarnation") == 0 => return,
                    "start" => format!(
                        "NODE {name} starts again (incarnation {})",
                        u(v, "incarnation")
                    ),
                    "stop" => return,
                    "kill" => format!("NODE {name} killed by the {}", s(v, "by")),
                    "machine-crash" => {
                        format!("NODE {name}'s machine crashes (by the {})", s(v, "by"))
                    }
                    "crash" => format!("NODE {name} ends on signal {}", u(v, "signal")),
                    "exit" => format!("NODE {name} exits with status {}", u(v, "exit")),
                    "pause" => format!("NODE {name} paused by the {}", s(v, "by")),
                    "resume" => format!("NODE {name} resumes after {} ms", u(v, "paused_ms")),
                    "clock" => format!(
                        "NODE {name}'s clock {} {} ms (offset {} ms)",
                        if v["skew_ms"].is_null() {
                            "steps"
                        } else {
                            "is skewed"
                        },
                        v["step_ms"].as_i64().or(v["skew_ms"].as_i64()).unwrap_or(0),
                        v["offset_ms"].as_i64().unwrap_or(0)
                    ),
                    _ => return,
                };
                self.push(v, String::new(), "node", text);
            }
            "mark" => {
                self.turn(v);
                let who = self.who(v);
                let text = format!("mark {} {}", s(v, "label"), s(v, "text"))
                    .trim_end()
                    .to_string();
                self.push(v, who, "mark", text);
            }
            "sdk" => {
                self.turn(v);
                let who = self.who(v);
                match s(v, "op") {
                    "assert" => {
                        self.push(v, who, "sdk", format!("assert {}", s(v, "label")));
                    }
                    "buggify" if u(v, "ret") == 1 => {
                        self.push(v, who, "fault", format!("BUGGIFY {} fired", s(v, "label")));
                    }
                    _ => {}
                }
            }
            "signal" | "sigfault" => {
                self.turn(v);
                let who = self.who(v);
                let sig = u(v, "sig");
                let text = if ty == "signal" {
                    format!("takes signal {sig}")
                } else {
                    format!("faults: signal {sig} at address {:#x}", u(v, "addr"))
                };
                self.push(v, who, "signal", text);
            }
            "preempt" => {
                self.st.preempts += 1;
                self.turn(v);
                if let Some(t) = self.turn.as_mut() {
                    t.preempts += 1;
                }
            }
            "sched" => {
                if s(v, "op") == "Hello" {
                    self.pids.insert(u(v, "slot") as u16, u(v, "pid"));
                }
                self.turn(v);
                let slot = u(v, "slot");
                let end = match s(v, "op") {
                    "Yield" if u(v, "ret") != slot => Some("switched out by the seed"),
                    "FutexWait" => Some("waits (a lock or a condition)"),
                    "Park" => Some("waits for I/O"),
                    "Sleep" => Some("sleeps"),
                    "ThreadExit" => Some("ends"),
                    "ProcExit" => Some("its process ends"),
                    "WaitPark" => Some("waits for a child"),
                    _ => None,
                };
                if let (Some(e), Some(t)) = (end, self.turn.as_mut()) {
                    t.end = Some(e);
                }
            }
            "insn" => self.turn(v),
            _ => {}
        }
    }

    fn call(&mut self, v: &Value) {
        self.turn(v);
        if let Some(t) = self.turn.as_mut() {
            t.calls += 1;
        }
        let name = s(v, "name");
        let ret = v["ret"].as_i64().unwrap_or(0);
        let args: Vec<i64> = v["args"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
            .unwrap_or_default();
        let who = self.who(v);
        match name {
            "exit_group" => {
                self.push(
                    v,
                    who,
                    "exits",
                    format!("exits with status {}", args.first().copied().unwrap_or(0)),
                );
                return;
            }
            "clone" | "clone3" | "fork" | "vfork" if ret > 0 => {
                // `clone` with CLONE_THREAD makes a thread; anything else a process.
                let thread = name == "clone" && args.first().is_some_and(|f| f & 0x10000 != 0);
                if let Some(t) = self.turn.as_mut() {
                    *if thread { &mut t.threads } else { &mut t.procs } += 1;
                }
                return;
            }
            "futex"
                if ret > 0
                    && args
                        .get(1)
                        .is_some_and(|op| matches!(op & 0x7f, 1 | 3 | 4 | 5)) =>
            {
                if let Some(t) = self.turn.as_mut() {
                    t.woken += ret as u64;
                }
                return;
            }
            "connect" | "sendto" | "sendmsg" | "recvfrom" | "recvmsg" | "write" | "read"
                if matches!(ret.checked_neg(), Some(32 | 101 | 104 | 110 | 111 | 113)) =>
            {
                let e = match ret.checked_neg().unwrap_or(0) {
                    32 => "EPIPE",
                    101 => "ENETUNREACH",
                    104 => "ECONNRESET",
                    110 => "ETIMEDOUT",
                    111 => "ECONNREFUSED",
                    _ => "EHOSTUNREACH",
                };
                self.push(v, who, "error", format!("{name} fails: {e}"));
                return;
            }
            _ => {}
        }
        if ret <= 0 {
            return;
        }
        let inc = u(v, "inc") as usize;
        let key = (u(v, "seq"), u(v, "slot") as u16);
        let Some(o) = self.obs.get(inc).and_then(|m| m.get(&key)).cloned() else {
            // No observation (not a data call, or none kept): output by its size.
            if name == "write" && matches!(args.first(), Some(1 | 2)) {
                let to = if args[0] == 2 { " to stderr" } else { "" };
                self.push(v, who, "prints", format!("prints{to} {ret} bytes"));
            }
            return;
        };
        let write = matches!(
            name,
            "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" | "sendto" | "sendmsg"
        );
        let q = quote(&o.bytes, o.cut);
        if write && matches!(o.fd, 1 | 2) && matches!(o.ftype, S_REG | S_CHR) {
            let to = if o.fd == 2 { " to stderr" } else { "" };
            self.push(v, who, "prints", format!("prints{to} {q}"));
            return;
        }
        match o.ftype {
            S_SOCK if o.conn != 0 => {
                let c = (inc, o.conn);
                if self.nodes.is_empty() {
                    self.ends
                        .entry(c)
                        .or_default()
                        .push((self.events, who.clone()));
                }
                if !write {
                    return; // the send is told, with its receiver
                }
                if self.nodes.is_empty() {
                    let i = self.push(v, who, "msg", format!("-> conn {} {q}", o.conn));
                    self.sends.push((i, c, self.events, q));
                    return;
                }
                // A node's peer is the node at the connection's other address (its own on
                // loopback).
                let peer = proto::wire::addr_node(o.raddr)
                    .and_then(|k| self.nodes.get(k).cloned())
                    .unwrap_or_else(|| who.clone());
                self.push(v, who, "msg", format!("-> {peer} {q}"));
            }
            S_SOCK | S_FIFO => {
                // A pipe or a local socket: its reader is the one that read the same bytes.
                if write {
                    let i = self.push(v, who, "msg", format!("-> ? {q}"));
                    if let Some(h) = v["in"].as_str() {
                        self.pipes.insert(h.to_string(), i);
                    }
                } else if let Some(i) = v["out"].as_str().and_then(|h| self.pipes.remove(h)) {
                    if self.st.lines[i].who != who {
                        let t = self.st.lines[i]
                            .text
                            .replacen("-> ?", &format!("-> {who}"), 1);
                        self.st.lines[i].text = t;
                    }
                }
            }
            _ => {}
        }
    }

    fn op(&mut self, v: &Value) {
        let op = s(v, "op");
        let node = v["node"].as_str().unwrap_or("").to_string();
        let p = path(v, "path");
        let name = p.clone();
        match op {
            "write" | "mmap-dirty" => {
                let f = self.files.entry((node.clone(), p.clone())).or_default();
                f.since += 1;
                f.writes += 1;
            }
            "fsync" => {
                let f = self.files.entry((node.clone(), p.clone())).or_default();
                f.since = 0;
                f.fsyncs += 1;
            }
            "sync" => {
                for ((n, _), f) in self.files.iter_mut() {
                    if *n == node {
                        f.since = 0;
                    }
                }
            }
            _ => {}
        }
        let what = match op {
            "write" => format!("write {name} ({} bytes at {})", u(v, "len"), u(v, "off")),
            "rename" => format!("rename {name} to {}", path(v, "to")),
            "create" | "mkdir" | "unlink" | "rmdir" | "truncate" | "fsync" | "fsync-fail"
            | "link" | "symlink" | "fallocate" => format!("{op} {name}"),
            "fsync-dir" => format!("fsync the directory {name}"),
            "sync" => "sync".to_string(),
            _ => return,
        };
        // An operation's actor: its node, or on one machine the thread whose turn it is.
        let who = if !self.nodes.is_empty() {
            node
        } else {
            match &self.turn {
                Some(t) => self.st.lines[t.line].who.clone(),
                None => self
                    .st
                    .lines
                    .last()
                    .filter(|l| l.kind != "crash")
                    .map_or("main".into(), |l| l.who.clone()),
            }
        };
        // Consecutive operations of one actor make one line, until its first comes again.
        let first = what.split(' ').take(2).collect::<Vec<_>>().join(" ");
        if let Some((i, f)) = &self.disk {
            let i = *i;
            let l = &self.st.lines[i];
            if i + 1 == self.st.lines.len()
                && l.who == who
                && *f != first
                && l.text.len() < DISK_LINE
            {
                self.st.lines[i].text += &format!(", {what}");
                return;
            }
        }
        let i = self.push(v, who, "disk", format!("disk: {what}"));
        self.disk = Some((i, first));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name or label from the program reaches the terminal with no control or
    /// direction-changing character; one without any is unchanged.
    #[test]
    fn names_are_cleaned() {
        let plain = "/work/data.log é";
        assert_eq!(clean(plain), plain);
        for s in ["/work/\x1b]52;c;aGk=\x07", "a\rb\n", "x\u{202e}y\u{85}"] {
            let c = clean(s);
            assert!(
                !c.chars()
                    .any(|c| c.is_control() || ('\u{2000}'..='\u{206f}').contains(&c)),
                "{c}"
            );
        }
    }

    /// Any bytes come out as printable ASCII on one line, bounded, marked when cut.
    #[test]
    fn payloads_are_escaped_and_cut() {
        let all: Vec<u8> = (0..=255u8).collect();
        for b in [
            &all[..],
            b"VOTE 1\n",
            b"\x1b[2J\x07\r",
            "h\u{e9}llo".as_bytes(),
            b"",
        ] {
            for more in [false, true] {
                let q = quote(b, more);
                assert!(q.chars().all(|c| c.is_ascii_graphic() || c == ' '), "{q}");
                assert!(q.len() <= SHOW + 5, "{q}");
                let inner = q.trim_end_matches("...");
                assert!(inner.starts_with('"') && inner.ends_with('"'));
                // Cut when the call moved more or the bytes did not fit; whole otherwise.
                if more || b.len() > SHOW {
                    assert!(q.ends_with("..."), "{q}");
                } else if b.len() * 4 <= SHOW {
                    assert!(!q.ends_with("..."), "{q}");
                }
            }
        }
        // What fits is all there.
        let q = quote(b"a\"b\\c\n\x00'", false);
        assert_eq!(q, "\"a\\\"b\\\\c\\n\\x00'\"");
    }

    /// Observations read back as they were made, whatever their length; records of another
    /// kind, a truncated file and a stray byte record are ignored.
    #[test]
    fn observations_round_trip() {
        let mut log = vec![];
        let mut want = HashMap::new();
        for (i, n) in [0usize, 1, 63, 64, 65, 128].into_iter().enumerate() {
            let bytes: Vec<u8> = (0..n).map(|j| (j * 31 + i) as u8).collect();
            let head = [3, S_SOCK, 7 + i as u64, 2, 0x11, 0];
            let seq = 10 + i as u64;
            for r in Rec::observed(seq, 5, 1, 42, head, &bytes, n == 128) {
                log.extend_from_slice(r.as_bytes());
            }
            let other = Rec {
                seq,
                kind: RecKind::Trap as u8,
                ..Rec::default()
            };
            log.extend_from_slice(other.as_bytes());
            want.insert(
                (seq, 1u16),
                Obs {
                    fd: 3,
                    ftype: S_SOCK,
                    conn: 7 + i as u64,
                    raddr: 0x11,
                    pid: 42,
                    bytes,
                    cut: n == 128,
                },
            );
        }
        let stray = Rec {
            kind: RecKind::Observe as u8,
            class: OBS_DATA,
            seq: 99,
            ..Rec::default()
        };
        log.extend_from_slice(stray.as_bytes());
        log.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            parse_observations(log.as_chunks::<REC_SIZE>().0.iter().copied()),
            want
        );
    }

    fn line(who: &str, text: &str) -> Line {
        Line {
            seq: 1,
            t: 0,
            who: who.into(),
            kind: "msg",
            text: text.into(),
            quiet: false,
        }
    }

    /// A block that repeats with other numbers folds to its first copy and a count; lines
    /// that differ in more than numbers do not.
    #[test]
    fn repeats_fold() {
        let mut ls = vec![line("a", "start")];
        for i in 0..5 {
            ls.push(line("a", &format!("-> b \"PING {i}\"")));
            ls.push(line("b", &format!("-> a \"PONG {i}\"")));
        }
        ls.push(line("a", "end"));
        let f = fold(&ls);
        assert_eq!(f.len(), 1 + 2 + 1 + 1);
        assert_eq!(f[3].kind, "fold");
        assert!(f[3].text.contains('5'));
        let two = vec![line("a", "x 1"), line("a", "x 2"), line("a", "y")];
        assert_eq!(fold(&two).len(), 3);
    }
}
