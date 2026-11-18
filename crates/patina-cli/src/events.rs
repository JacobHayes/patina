//! `patina log events RUNDIR`: one JSON object per line of what a run did, read from its run
//! directory and nothing else: the boundary log's records (calls, SDK calls, injected faults,
//! crashes, signals, scheduling) merged with the operation log's file operations, each named by
//! its path at that moment. The stable export a checker reads; its fields are documented in
//! docs/GUIDE.md ("The event stream") and only ever added to.
//!
//! Streaming: both logs are read record by record; what is kept is the namespace of the work
//! tree (one entry per live name), never the log.

use crate::cli::Res;
use crate::durability::check::incarnations;
use crate::durability::tree::Tree;
use crate::log::Cut;
use proto::ctl::Op;
use proto::oplog::{OpKind, OpRec, OPREC_SIZE};
use proto::rec::{Rec, RecKind, REC_SIZE};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// The schema version in the header line.
pub const VERSION: u32 = 1;

/// Every event type, in the order the guide lists them.
pub const TYPES: [&str; 14] = [
    "header", "inc", "cut", "call", "op", "fault", "crash", "mark", "sdk", "signal", "sigfault",
    "sched", "preempt", "insn",
];

/// What to print: the types (`None`: all) and the sequence range of events that have one.
pub struct Select {
    pub types: Option<Vec<String>>,
    pub from: u64,
    pub to: u64,
}

impl Select {
    pub fn parse(types: Option<&str>, from: u64, to: u64) -> Res<Select> {
        let types = match types {
            None => None,
            Some(s) => {
                let v: Vec<String> = s.split(',').map(|t| t.trim().to_string()).collect();
                for t in &v {
                    if !TYPES.contains(&t.as_str()) {
                        return Err(format!(
                            "--types: unknown type {t:?} (types: {})",
                            TYPES.join(", ")
                        ));
                    }
                }
                Some(v)
            }
        };
        Ok(Select { types, from, to })
    }
    fn wants(&self, ty: &str) -> bool {
        self.types
            .as_ref()
            .is_none_or(|v| v.iter().any(|t| t == ty))
    }
    fn in_range(&self, seq: u64) -> bool {
        seq >= self.from && seq <= self.to
    }
}

/// A JSON line being built: `{"type":T,"inc":K,...}`.
struct Line(String);

impl Line {
    fn new(ty: &str, inc: usize) -> Line {
        Line(format!("{{\"type\":\"{ty}\",\"inc\":{inc}"))
    }
    fn at(ty: &str, inc: usize, r: &Rec) -> Line {
        let mut l = Line::new(ty, inc);
        l.num("seq", r.seq)
            .num("t", r.vclock_ns)
            .num("slot", r.slot);
        l
    }
    fn num(&mut self, k: &str, v: impl std::fmt::Display) -> &mut Line {
        let _ = write!(self.0, ",\"{k}\":{v}");
        self
    }
    fn str(&mut self, k: &str, v: &str) -> &mut Line {
        let _ = write!(self.0, ",\"{k}\":{}", Value::from(v));
        self
    }
    fn hex(&mut self, k: &str, v: u64) -> &mut Line {
        if v != 0 {
            let _ = write!(self.0, ",\"{k}\":\"{v:016x}\"");
        }
        self
    }
    fn raw(&mut self, k: &str, v: &str) -> &mut Line {
        let _ = write!(self.0, ",\"{k}\":{v}");
        self
    }
    fn done(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

enum Item {
    Rec(Rec),
    Cut(Cut),
}

/// An incarnation's boundary records in log order: `boundary.log`, and for a cut log the
/// `Cut` and then `boundary.tail`. Two records of lookahead (an injected fault's names).
struct Records {
    cur: Option<(BufReader<File>, PathBuf)>,
    tail: Option<(PathBuf, Cut)>,
    ahead: VecDeque<Item>,
}

fn open(p: &Path) -> Res<File> {
    File::open(p).map_err(|e| format!("{}: {e}", p.display()))
}

impl Records {
    fn open(inc: &Path) -> Res<Records> {
        let log = inc.join("boundary.log");
        let tail = match crate::result::read_json(&inc.join("boundary.cut")) {
            Ok(c) => Some((
                inc.join("boundary.tail"),
                serde_json::from_value(c).map_err(|e| format!("{}: {e}", inc.display()))?,
            )),
            Err(_) => None,
        };
        Ok(Records {
            cur: Some((BufReader::with_capacity(1 << 20, open(&log)?), log)),
            tail,
            ahead: VecDeque::new(),
        })
    }

    fn read(&mut self) -> Res<Option<Item>> {
        loop {
            let Some((f, path)) = &mut self.cur else {
                return Ok(None);
            };
            let mut b = [0u8; REC_SIZE];
            let mut n = 0;
            while n < REC_SIZE {
                match f.read(&mut b[n..]) {
                    Ok(0) => break,
                    Ok(k) => n += k,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(format!("{}: {e}", path.display())),
                }
            }
            if n == REC_SIZE {
                return Ok(Some(Item::Rec(Rec::from_bytes(&b))));
            }
            if n != 0 {
                return Err(format!(
                    "{}: ends in a partial record ({n} of {REC_SIZE} bytes)",
                    path.display()
                ));
            }
            self.cur = None;
            if let Some((p, c)) = self.tail.take() {
                self.cur = Some((BufReader::with_capacity(1 << 20, open(&p)?), p));
                return Ok(Some(Item::Cut(c)));
            }
        }
    }

    fn next(&mut self) -> Res<Option<Item>> {
        match self.ahead.pop_front() {
            Some(i) => Ok(Some(i)),
            None => self.read(),
        }
    }

    /// The `i`-th record after the current one (0: the next), if it is a record.
    fn peek(&mut self, i: usize) -> Res<Option<Rec>> {
        while self.ahead.len() <= i {
            match self.read()? {
                Some(x) => self.ahead.push_back(x),
                None => return Ok(None),
            }
        }
        Ok(match &self.ahead[i] {
            Item::Rec(r) => Some(*r),
            Item::Cut(_) => None,
        })
    }
}

/// One operation record and, for the kinds that name something, its names.
struct OpEv {
    r: OpRec,
    kind: Option<OpKind>,
    /// The name (created, linked, removed, renamed from, the attribute's).
    name: Vec<u8>,
    /// A rename's new name, a symlink's target.
    second: Vec<u8>,
}

/// The operation log, record by record; names read from `oplog.data` where needed.
struct Ops {
    meta: BufReader<File>,
    data: File,
    next: Option<OpEv>,
    path: PathBuf,
}

impl Ops {
    /// `None` when the incarnation has no operation log (a sweep removes a large one).
    fn open(inc: &Path) -> Res<Option<Ops>> {
        let (m, d) = (inc.join("oplog.meta"), inc.join("oplog.data"));
        if !m.exists() || !d.exists() {
            return Ok(None);
        }
        let mut o = Ops {
            meta: BufReader::with_capacity(1 << 20, open(&m)?),
            data: open(&d)?,
            next: None,
            path: m,
        };
        o.advance()?;
        Ok(Some(o))
    }

    fn bytes(&self, off: u64, len: u64) -> Res<Vec<u8>> {
        let mut b = vec![0u8; len as usize];
        self.data
            .read_exact_at(&mut b, off)
            .map_err(|e| format!("{}: data: {e}", self.path.display()))?;
        Ok(b)
    }

    fn advance(&mut self) -> Res<()> {
        let mut b = [0u8; OPREC_SIZE];
        let mut n = 0;
        while n < OPREC_SIZE {
            match self.meta.read(&mut b[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("{}: {e}", self.path.display())),
            }
        }
        if n < OPREC_SIZE {
            self.next = None;
            return Ok(());
        }
        let r = OpRec::from_bytes(&b);
        let kind = OpKind::from_u32(r.kind);
        let (o, l, a) = (r.data_off, r.data_len, r.a);
        let (name, second) = match kind {
            Some(
                OpKind::Create
                | OpKind::Mkdir
                | OpKind::Link
                | OpKind::Unlink
                | OpKind::Rmdir
                | OpKind::XattrRemove,
            ) => (self.bytes(o, l)?, vec![]),
            Some(OpKind::Symlink) => {
                let b = self.bytes(o, l)?;
                let k = (a[1] as usize).min(b.len());
                (b[..k].to_vec(), b[k..].to_vec())
            }
            Some(OpKind::Rename) => {
                let b = self.bytes(o, l)?;
                let k = (a[4] as usize).min(b.len());
                (b[..k].to_vec(), b[k..].to_vec())
            }
            Some(OpKind::XattrSet) => (self.bytes(o, a[0].min(l))?, vec![]),
            _ => (vec![], vec![]),
        };
        self.next = Some(OpEv {
            r,
            kind,
            name,
            second,
        });
        Ok(())
    }

    fn take(&mut self) -> Res<Option<OpEv>> {
        let o = self.next.take();
        self.advance()?;
        Ok(o)
    }
}

/// The work tree's names as the operations go by: each inode's links in the order they were
/// made. A path names an inode's first link that still exists.
struct Names {
    at: String,
    root: u64,
    links: HashMap<u64, Vec<(u64, Vec<u8>)>>,
}

const RENAME_EXCHANGE: u64 = 2;

impl Names {
    fn path(&self, ino: u64) -> Option<String> {
        let mut parts: Vec<&[u8]> = vec![];
        let mut i = ino;
        // Bounded: a tree of directories has no cycle, but a corrupt log might.
        for _ in 0..4096 {
            if i == self.root {
                let mut s = self.at.clone();
                for p in parts.iter().rev() {
                    s.push('/');
                    s.push_str(&String::from_utf8_lossy(p));
                }
                return Some(s);
            }
            let (parent, name) = self.links.get(&i)?.first()?;
            parts.push(name);
            i = *parent;
        }
        None
    }
    fn child(&self, parent: u64, name: &[u8]) -> Option<String> {
        self.path(parent)
            .map(|p| format!("{p}/{}", String::from_utf8_lossy(name)))
    }
    fn link(&mut self, ino: u64, parent: u64, name: &[u8]) {
        self.links
            .entry(ino)
            .or_default()
            .push((parent, name.to_vec()));
    }
    fn unlink(&mut self, ino: u64, parent: u64, name: &[u8]) {
        if let Some(v) = self.links.get_mut(&ino) {
            v.retain(|(p, n)| !(*p == parent && n == name));
            if v.is_empty() {
                self.links.remove(&ino);
            }
        }
    }
    /// Apply an operation; for the ones that name a path, the event's `path` (and `to`), taken
    /// at the moment of the operation: a new name after it, a removed or old one before it.
    fn apply(&mut self, o: &OpEv) -> (Option<String>, Option<String>) {
        let (ino, a) = (o.r.ino, o.r.a);
        match o.kind {
            Some(OpKind::Root) => {
                self.root = ino;
                (Some(self.at.clone()), None)
            }
            Some(OpKind::Create | OpKind::Mkdir | OpKind::Symlink | OpKind::Link) => {
                self.link(ino, a[0], &o.name);
                (self.child(a[0], &o.name), None)
            }
            Some(OpKind::Unlink | OpKind::Rmdir) => {
                let p = self.child(a[0], &o.name);
                self.unlink(ino, a[0], &o.name);
                (p, None)
            }
            Some(OpKind::Rename) => {
                let (from, to) = (self.child(a[0], &o.name), self.child(a[1], &o.second));
                let replaced = a[2];
                self.unlink(ino, a[0], &o.name);
                if replaced != 0 && replaced != ino {
                    self.unlink(replaced, a[1], &o.second);
                    if a[3] & RENAME_EXCHANGE != 0 {
                        self.link(replaced, a[0], &o.name);
                    }
                }
                self.link(ino, a[1], &o.second);
                (from, to)
            }
            _ if ino == 0 => (None, None),
            _ => (self.path(ino), None),
        }
    }
}

/// The name an event gives an operation kind.
fn op_name(k: OpKind) -> &'static str {
    match k {
        OpKind::Root => "root",
        OpKind::Create => "create",
        OpKind::Mkdir => "mkdir",
        OpKind::Symlink => "symlink",
        OpKind::Link => "link",
        OpKind::Unlink => "unlink",
        OpKind::Rmdir => "rmdir",
        OpKind::Rename => "rename",
        OpKind::Write => "write",
        OpKind::Truncate => "truncate",
        OpKind::Fallocate => "fallocate",
        OpKind::SetAttr => "setattr",
        OpKind::XattrSet => "xattr-set",
        OpKind::XattrRemove => "xattr-remove",
        OpKind::MmapShared => "mmap-shared",
        OpKind::MmapDirty => "mmap-dirty",
        OpKind::Fsync => "fsync",
        OpKind::FsyncDir => "fsync-dir",
        OpKind::FsyncFail => "fsync-fail",
        OpKind::Sync => "sync",
        OpKind::Close => "close",
        OpKind::Crash => "crash",
    }
}

fn sdk_op(op: u64) -> &'static str {
    use proto::sdk::*;
    match op {
        OP_HELLO => "hello",
        OP_ASSERT => "assert",
        OP_BUGGIFY => "buggify",
        OP_KNOB => "knob",
        OP_DELAY => "delay",
        OP_MARK => "mark",
        OP_DECLARE => "declare",
        OP_COMPUTE_HELLO => "compute-hello",
        OP_COMPUTE_POINT => "compute-point",
        _ => "unknown",
    }
}

/// One run's export.
struct Export<'a, W: Write> {
    out: W,
    sel: &'a Select,
    result: Option<Value>,
    work: String,
}

impl<W: Write> Export<'_, W> {
    fn emit(&mut self, ty: &str, seq: Option<u64>, line: Line) -> Res<()> {
        // The header is always printed: it says what the stream is.
        let wanted = ty == "header" || self.sel.wants(ty);
        if !wanted || seq.is_some_and(|s| !self.sel.in_range(s)) {
            return Ok(());
        }
        writeln!(self.out, "{}", line.done()).map_err(|e| e.to_string())
    }

    fn op(&mut self, k: usize, names: &mut Names, o: &OpEv) -> Res<()> {
        let (path, to) = names.apply(o);
        let Some(kind) = o.kind else {
            return Ok(());
        };
        // Base records are the incarnation's starting tree, not operations; the `Crash`
        // record is the `crash` event's.
        if o.r.seq == 0 || kind == OpKind::Crash {
            return Ok(());
        }
        let (r, a) = (&o.r, o.r.a);
        let mut l = Line::new("op", k);
        l.num("seq", r.seq)
            .num("t", r.vclock_ns)
            .num("pid", r.pid)
            .str("op", op_name(kind))
            .num("ino", r.ino);
        if let Some(p) = &path {
            l.str("path", p);
        }
        match kind {
            OpKind::Create => {
                l.num("mode", a[1] & 0o7777).num("fmt", a[2]);
            }
            OpKind::Mkdir => {
                l.num("mode", a[1] & 0o7777);
            }
            OpKind::Symlink => {
                l.str("target", &String::from_utf8_lossy(&o.second));
            }
            OpKind::Unlink | OpKind::Rmdir => {
                l.num("left", a[1]);
            }
            OpKind::Rename => {
                if let Some(t) = &to {
                    l.str("to", t);
                }
                if a[2] != 0 {
                    l.num("replaced", a[2]);
                }
                l.num("flags", a[3]);
            }
            OpKind::Write | OpKind::MmapDirty | OpKind::MmapShared => {
                l.num("off", a[0]).num("len", a[1]);
            }
            OpKind::Truncate => {
                l.num("size", a[0]);
            }
            OpKind::Fallocate => {
                l.num("mode", a[0]).num("off", a[1]).num("len", a[2]);
            }
            OpKind::SetAttr => {
                l.num("mode", a[0] & 0o7777)
                    .num("uid", a[1])
                    .num("gid", a[2]);
            }
            OpKind::XattrSet | OpKind::XattrRemove => {
                l.str("name", &String::from_utf8_lossy(&o.name));
            }
            OpKind::Fsync => {
                l.num("flags", a[0]);
            }
            _ => {}
        }
        self.emit("op", Some(r.seq), l)
    }

    fn crash(&mut self, k: usize, inc: &Path, r: &Rec) -> Res<()> {
        // The crash's `seq` is its call's, as in `result.json`.
        let mut l = Line::new("crash", k);
        l.num("seq", r.args[1])
            .num("t", r.vclock_ns)
            .num("slot", r.slot);
        let kind = crate::sup::crash::crash_name(r.args[0]);
        l.str("kind", kind);
        let c = self
            .result
            .as_ref()
            .and_then(|v| v["crashes"].as_array())
            .and_then(|a| a.iter().find(|c| c["incarnation"] == k as u64));
        if let Some(p) = c.and_then(|c| c["point"].as_u64()) {
            l.num("point", p);
        }
        // What a machine crash did to the work tree, as `faults.recent` shows it.
        let (live, post) = (inc.join("live.tree"), inc.join("post-crash"));
        if kind == "machine" && live.is_file() && post.is_dir() {
            if let (Ok(live), Ok(post)) = (Tree::read_archive(&live), Tree::from_dir(&post)) {
                let lost = crate::launcher::attribution::lost(&live, &post, &self.work);
                l.raw("lost", &lost.to_string());
            }
        }
        self.emit("crash", Some(r.args[1]), l)
    }

    fn record(&mut self, k: usize, inc: &Path, recs: &mut Records, r: &Rec) -> Res<()> {
        let a = r.args;
        match RecKind::from_u8(r.kind) {
            Some(RecKind::Trap) if r.nr as u64 == proto::sdk::SYSCALL => {
                let op = sdk_op(a[0]);
                let ty = if a[0] == proto::sdk::OP_MARK {
                    "mark"
                } else {
                    "sdk"
                };
                let mut l = Line::at(ty, k, r);
                if ty == "sdk" {
                    l.str("op", op);
                }
                // The payload's label and text: their length and the payload's hash (the
                // same label and text, the same hash).
                if (proto::sdk::OP_ASSERT..=proto::sdk::OP_DECLARE).contains(&a[0]) {
                    l.num("len", a[2].saturating_sub(proto::sdk::HDR_LEN as u64));
                    l.hex("hash", r.in_hash);
                }
                l.num("ret", r.ret);
                self.emit(ty, Some(r.seq), l)
            }
            Some(RecKind::Trap) => {
                let nr = r.nr as u64;
                let mut l = Line::at("call", k, r);
                let name = proto::table::name(nr);
                l.str("name", name);
                if name == "unknown" {
                    l.num("nr", nr);
                }
                let n = proto::table::nargs::NARGS
                    .get(r.nr as usize)
                    .copied()
                    .unwrap_or(6) as usize;
                let mut s = String::from("[");
                for (i, v) in a[..n.min(6)].iter().enumerate() {
                    let _ = write!(s, "{}{}", if i > 0 { "," } else { "" }, *v as i64);
                }
                s.push(']');
                l.raw("args", &s).num("ret", r.ret).str(
                    "disp",
                    &proto::table::Class::code_name(r.class).to_ascii_lowercase(),
                );
                l.hex("in", r.in_hash).hex("out", r.out_hash);
                self.emit("call", Some(r.seq), l)
            }
            Some(RecKind::Injected) => {
                let (n1, n2) = (recs.peek(0)?, recs.peek(1)?);
                let (_, e) = crate::launcher::attribution::injected(r, n1, n2);
                let mut l = Line::at("fault", k, r);
                // `faults.recent`'s fields; its `fault` is the class, its `thread` the slot.
                if let Value::Object(m) = e {
                    for (key, v) in m.iter().filter(|(key, _)| *key != "thread") {
                        let key = if key == "fault" { "class" } else { key };
                        l.raw(key, &v.to_string());
                    }
                }
                self.emit("fault", Some(r.seq), l)
            }
            // An injected fault's names, read with it.
            Some(RecKind::Name) => Ok(()),
            Some(RecKind::SupDecision) if r.nr == Op::CrashPoint as u32 => self.crash(k, inc, r),
            Some(RecKind::SupDecision) => {
                let mut l = Line::at("sched", k, r);
                let op = Op::from_u32(r.nr).map_or("unknown", |o| o.name());
                l.str("op", op).num("ret", r.ret);
                self.emit("sched", Some(r.seq), l)
            }
            Some(RecKind::Preempt) => {
                let mut l = Line::at("preempt", k, r);
                let why = match r.nr {
                    1 => "counter",
                    2 => "spin-point",
                    proto::compute::PREEMPT_NR => "compute",
                    _ => "unknown",
                };
                l.str("why", why).num("pc", a[0]);
                self.emit("preempt", Some(r.seq), l)
            }
            Some(RecKind::SignalDelivery) => {
                let mut l = Line::at("signal", k, r);
                l.num("sig", r.nr)
                    .num("code", a[2] as u32 as i32)
                    .num("pc", a[3]);
                self.emit("signal", Some(r.seq), l)
            }
            Some(RecKind::Fault) => {
                let mut l = Line::at("sigfault", k, r);
                l.num("sig", r.nr)
                    .num("code", a[1] as u32 as i32)
                    .num("addr", a[2])
                    .num("pc", a[0]);
                self.emit("sigfault", Some(r.seq), l)
            }
            Some(RecKind::InsnEmulation) => {
                let mut l = Line::at("insn", k, r);
                l.str("insn", &crate::log::insn_name(r.nr))
                    .num("ret", r.ret);
                self.emit("insn", Some(r.seq), l)
            }
            _ => Ok(()),
        }
    }

    fn incarnation(&mut self, k: usize, inc: &Path) -> Res<()> {
        let mut recs = Records::open(inc)?;
        let mut ops = Ops::open(inc)?;
        let records = std::fs::metadata(inc.join("boundary.log"))
            .map(|m| m.len() / REC_SIZE as u64)
            .unwrap_or(0);
        let records = match &recs.tail {
            Some((_, c)) => c.records,
            None => records,
        };
        let mut l = Line::new("inc", k);
        l.num("records", records)
            .raw("oplog", if ops.is_some() { "true" } else { "false" });
        self.emit("inc", None, l)?;
        let mut names = Names {
            at: self.work.clone(),
            root: 0,
            links: HashMap::new(),
        };
        while let Some(item) = recs.next()? {
            let r = match item {
                Item::Cut(c) => {
                    let mut l = Line::new("cut", k);
                    l.num("records", c.records)
                        .num("head", c.head)
                        .num("tail_from", c.tail_from);
                    self.emit("cut", None, l)?;
                    continue;
                }
                Item::Rec(r) => r,
            };
            // Operations whose call has no record (a crash between the two, a process's exit)
            // come before the first record after them in virtual time; a crash comes after
            // every operation before it.
            let crash = r.kind == RecKind::SupDecision as u8 && r.nr == Op::CrashPoint as u32;
            if let Some(o) = &mut ops {
                while let Some(n) = &o.next {
                    let before =
                        n.r.vclock_ns < r.vclock_ns || (crash && n.r.vclock_ns == r.vclock_ns);
                    if !before || n.r.seq == r.seq {
                        break;
                    }
                    let n = o.take()?.unwrap();
                    self.op(k, &mut names, &n)?;
                }
            }
            self.record(k, inc, &mut recs, &r)?;
            // A call's operations follow it.
            if r.kind == RecKind::Trap as u8 {
                if let Some(o) = &mut ops {
                    while o.next.as_ref().is_some_and(|n| n.r.seq == r.seq) {
                        let n = o.take()?.unwrap();
                        self.op(k, &mut names, &n)?;
                    }
                }
            }
        }
        if let Some(o) = &mut ops {
            while let Some(n) = o.take()? {
                self.op(k, &mut names, &n)?;
            }
        }
        Ok(())
    }
}

/// Print the stream of the run directory `run` to `out`.
pub fn export(run: &Path, sel: &Select, out: impl Write) -> Res<()> {
    let runjson = run.join("run.json");
    let incs = incarnations(run);
    if incs.is_empty() {
        return Err(if runjson.is_file() {
            format!(
                "{}: no logs: a sweep keeps only run.json and result.json of a run that ended ok \
                 (--keep all keeps them); patina replay {} --out DIR runs it again with its logs",
                run.display(),
                run.display()
            )
        } else {
            format!("{}: not a run directory (no inc-0)", run.display())
        });
    }
    let cfg = crate::result::read_json(&runjson).ok();
    let work = cfg
        .as_ref()
        .and_then(|c| c["config"]["work-at"].as_str().map(str::to_string))
        .unwrap_or_else(|| "/work".to_string());
    let mut x = Export {
        out: BufWriter::with_capacity(1 << 20, out),
        sel,
        result: crate::result::read_json(&run.join("result.json")).ok(),
        work,
    };
    let mut l = Line(format!("{{\"type\":\"header\",\"v\":{VERSION}"));
    if let Some(s) = cfg.as_ref().and_then(|c| c["config"]["seed"].as_u64()) {
        l.num("seed", s);
    }
    l.str("work", &x.work.clone())
        .num("incarnations", incs.len());
    x.emit("header", None, l)?;
    for (k, inc) in incs.iter().enumerate() {
        x.incarnation(k, inc)?;
    }
    x.out.flush().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(kind: OpKind, ino: u64, a: [u64; 6], name: &str, second: &str) -> OpEv {
        OpEv {
            r: OpRec {
                seq: 1,
                kind: kind as u32,
                ino,
                a,
                ..OpRec::default()
            },
            kind: Some(kind),
            name: name.as_bytes().to_vec(),
            second: second.as_bytes().to_vec(),
        }
    }

    /// Paths at the moment of each operation: a renamed file by its new name, a replaced one
    /// gone, an exchanged pair swapped, a file with two links by the first that remains.
    #[test]
    fn names_follow_the_operations() {
        let mut n = Names {
            at: "/w".into(),
            root: 0,
            links: HashMap::new(),
        };
        n.apply(&op(OpKind::Root, 1, [0; 6], "", ""));
        n.apply(&op(OpKind::Mkdir, 2, [1, 0o755, 0, 0, 0, 0], "d", ""));
        n.apply(&op(OpKind::Create, 3, [2, 0o644, 0, 0, 0, 0], "x", ""));
        n.apply(&op(OpKind::Create, 4, [1, 0o644, 0, 0, 0, 0], "y", ""));
        let r = n.apply(&op(OpKind::Rename, 3, [2, 1, 4, 0, 1, 0], "x", "y"));
        assert_eq!(r, (Some("/w/d/x".into()), Some("/w/y".into())));
        assert_eq!((n.path(3), n.path(4)), (Some("/w/y".into()), None));
        n.apply(&op(OpKind::Create, 5, [2, 0o644, 0, 0, 0, 0], "z", ""));
        n.apply(&op(OpKind::Rename, 3, [1, 2, 5, 2, 1, 0], "y", "z"));
        assert_eq!(
            (n.path(3), n.path(5)),
            (Some("/w/d/z".into()), Some("/w/y".into()))
        );
        n.apply(&op(OpKind::Link, 5, [2, 0, 0, 0, 0, 0], "l", ""));
        assert_eq!(n.path(5), Some("/w/y".into()));
        let r = n.apply(&op(OpKind::Unlink, 5, [1, 1, 0, 0, 0, 0], "y", ""));
        assert_eq!(r.0, Some("/w/y".into()));
        assert_eq!(n.path(5), Some("/w/d/l".into()));
        n.apply(&op(OpKind::Rename, 2, [1, 1, 0, 0, 1, 0], "d", "e"));
        assert_eq!(n.path(3), Some("/w/e/z".into()));
    }
}
