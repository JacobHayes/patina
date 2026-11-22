//! `patina log events RUNDIR`: one JSON object per line of what a run did, read from its run
//! directory and nothing else: the boundary log's records (calls, SDK calls, injected faults,
//! crashes, signals, scheduling) merged with the operation log's file operations, each named by
//! its path at that moment. The stable export a checker reads; its fields are documented in
//! `patina guide failures` and only ever added to.
//!
//! Streaming: both logs are read record by record; what is kept is the namespace of the work
//! tree (one entry per live name), never the log.

use crate::cli::Res;
use crate::durability::check::incarnations;
use crate::log::{Cut, Str};
use proto::ctl::Op;
use proto::oplog::{OpKind, OpRec, OPREC_SIZE};
use proto::rec::{
    Rec, RecKind, REC_SIZE, STR_ARGV, STR_ARGV_CUT, STR_LABEL, STR_PATH, STR_PATH2, STR_RESOLVED,
    STR_RESOLVED2, STR_TEXT,
};
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
pub const TYPES: [&str; 17] = [
    "header", "inc", "cut", "call", "op", "fault", "crash", "mark", "sdk", "signal", "sigfault",
    "sched", "preempt", "insn", "node", "net", "phase",
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
    /// Bytes from the program as a string: as they are when they are UTF-8; otherwise each
    /// invalid byte as U+FFFD and the exact bytes in `K_hex` (lowercase hex), so nothing is
    /// lost and a reader that wants the bytes has them.
    fn bytes(&mut self, k: &str, v: &[u8]) -> &mut Line {
        match std::str::from_utf8(v) {
            Ok(s) => self.str(k, s),
            Err(_) => {
                self.str(k, &String::from_utf8_lossy(v));
                let mut h = String::with_capacity(2 * v.len());
                for b in v {
                    let _ = write!(h, "{b:02x}");
                }
                self.str(&format!("{k}_hex"), &h)
            }
        }
    }
    /// A list of byte strings, as `bytes` does one (`K_hex` when any is not UTF-8).
    fn list(&mut self, k: &str, v: &[&[u8]]) -> &mut Line {
        let s: Vec<Value> = v
            .iter()
            .map(|b| String::from_utf8_lossy(b).into())
            .collect();
        self.raw(k, &Value::from(s).to_string());
        if v.iter().any(|b| std::str::from_utf8(b).is_err()) {
            let h: Vec<Value> = v
                .iter()
                .map(|b| {
                    b.iter()
                        .map(|c| format!("{c:02x}"))
                        .collect::<String>()
                        .into()
                })
                .collect();
            self.raw(&format!("{k}_hex"), &Value::from(h).to_string());
        }
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

    /// The strings that follow the record `r` (`Str` records of its call), taken from the
    /// stream. A string whose records a cut log lost is left out.
    fn strings(&mut self, r: &Rec) -> Res<Vec<Str>> {
        let mut v: Vec<Str> = vec![];
        while let Some(n) = self.peek(0)? {
            if n.kind != RecKind::Str as u8 || n.seq != r.seq || n.slot != r.slot {
                break;
            }
            self.next()?;
            if let Some(s) = v.last_mut().filter(|s| !s.whole()) {
                if s.push(&n) {
                    continue;
                }
            }
            if let Some(s) = Str::start(&n) {
                v.push(s);
            }
        }
        v.retain(Str::whole);
        Ok(v)
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
    fn new(at: String) -> Names {
        Names {
            at,
            root: 0,
            links: HashMap::new(),
        }
    }

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
        OP_CONTROL => "control",
        _ => "unknown",
    }
}

/// One run's export.
struct Export<'a, W: Write> {
    out: W,
    sel: &'a Select,
    result: Option<Value>,
    work: String,
    /// A run with nodes: their names (the driver first), each slot's node as the log says it
    /// (`DEC_NODE_SLOT`), and the node of the record being exported.
    nodes: Vec<String>,
    /// Each node's work tree (`work` of its `[node.NAME]`; the driver's is `work`).
    node_work: Vec<String>,
    slot_node: HashMap<u16, usize>,
    node: Option<usize>,
}

impl<W: Write> Export<'_, W> {
    fn emit(&mut self, ty: &str, seq: Option<u64>, mut line: Line) -> Res<()> {
        // The header is always printed: it says what the stream is.
        let wanted = ty == "header" || self.sel.wants(ty);
        if !wanted || seq.is_some_and(|s| !self.sel.in_range(s)) {
            return Ok(());
        }
        // With nodes, an event of a thread names the thread's node.
        if let Some(n) = self.node.and_then(|n| self.nodes.get(n)) {
            line.str("node", &n.clone());
        }
        writeln!(self.out, "{}", line.done()).map_err(|e| e.to_string())
    }

    fn node_name(&self, k: u64) -> String {
        self.nodes
            .get(k as usize)
            .cloned()
            .unwrap_or_else(|| k.to_string())
    }

    /// Node names of a bit set (`Op::Net`).
    fn node_set(&self, bits: u64) -> String {
        let v: Vec<Value> = (0..64)
            .filter(|b| bits & (1 << b) != 0)
            .map(|b| self.node_name(b).into())
            .collect();
        Value::from(v).to_string()
    }

    /// The node events (`node`, `net`) of a decision record, if it is one (an unanswered
    /// keepalive probe also in a run without nodes).
    fn node_record(&mut self, k: usize, r: &Rec) -> Option<Res<()>> {
        if r.kind != RecKind::SupDecision as u8
            || self.nodes.is_empty() && r.nr != proto::ctl::DEC_WIRE_PROBE
        {
            return None;
        }
        let a = r.args;
        let mut l;
        let ty = match r.nr {
            proto::ctl::DEC_NODE_SLOT => {
                self.slot_node.insert(a[0] as u16, a[1] as usize);
                return Some(Ok(()));
            }
            proto::ctl::DEC_NODE_START | proto::ctl::DEC_NODE_STOP => {
                l = Line::at("node", k, r);
                let start = r.nr == proto::ctl::DEC_NODE_START;
                l.str("event", if start { "start" } else { "stop" })
                    .str("name", &self.node_name(a[0]));
                if start {
                    l.num("pid", a[1]);
                    // A restart's incarnation (the run's first start of every node is 0).
                    if a[2] > 0 {
                        l.num("incarnation", a[2]);
                    }
                } else {
                    l.num("live", a[1]);
                }
                "node"
            }
            // [node, incarnation, how, exit status or signal, processes killed, down ns].
            proto::ctl::DEC_NODE_DOWN => {
                use proto::node::*;
                l = Line::at("node", k, r);
                let (event, by) = match a[2] {
                    DOWN_KILL_SEED => ("kill", Some("seed")),
                    DOWN_KILL_SCRIPT => ("kill", Some("script")),
                    DOWN_CRASH_SEED => ("machine-crash", Some("seed")),
                    DOWN_CRASH_SCRIPT => ("machine-crash", Some("script")),
                    DOWN_SIGNAL => ("crash", None),
                    _ => ("exit", None),
                };
                l.str("event", event)
                    .str("name", &self.node_name(a[0]))
                    .num("incarnation", a[1]);
                match (by, a[2]) {
                    (Some(by), _) => {
                        l.str("by", by);
                    }
                    (None, DOWN_SIGNAL) => {
                        l.num("signal", a[3]);
                    }
                    _ => {
                        l.num("exit", a[3]);
                    }
                }
                l.num("killed", a[4]);
                if a[5] > 0 {
                    l.num("restart_in_ms", a[5] / 1_000_000);
                }
                "node"
            }
            // [node, incarnation, by, ordinal, length ns (0: until a resume), 0].
            proto::ctl::DEC_NODE_PAUSE => {
                use proto::node::*;
                l = Line::at("node", k, r);
                l.str("event", "pause")
                    .str("name", &self.node_name(a[0]))
                    .num("incarnation", a[1])
                    .str("by", if a[2] == BY_SEED { "seed" } else { "script" })
                    .num("n", a[3]);
                if a[4] > 0 {
                    l.num("length_ms", a[4] / 1_000_000);
                }
                "node"
            }
            // [node, incarnation, how (`PEND_*`), ordinal, ns paused, 0].
            proto::ctl::DEC_NODE_RESUME => {
                l = Line::at("node", k, r);
                l.str("event", "resume")
                    .str("name", &self.node_name(a[0]))
                    .num("incarnation", a[1])
                    .str("by", proto::node::pause_end_name(a[2]))
                    .num("n", a[3])
                    .num("paused_ms", a[4] / 1_000_000);
                "node"
            }
            // [node, incarnation, how (`CLK_*`), change ns, offset ns, 0] (two's complement).
            proto::ctl::DEC_NODE_CLOCK => {
                l = Line::at("node", k, r);
                let skew = a[2] == proto::node::CLK_SKEW;
                l.str("event", "clock")
                    .str("name", &self.node_name(a[0]))
                    .num("incarnation", a[1])
                    .str("by", if skew { "seed" } else { "script" })
                    .raw(
                        if skew { "skew_ms" } else { "step_ms" },
                        &(a[3] as i64 / 1_000_000).to_string(),
                    )
                    .raw("offset_ms", &(a[4] as i64 / 1_000_000).to_string());
                "node"
            }
            n if n == Op::Net as u32 => {
                l = Line::at("net", k, r);
                let verb = match a[0] {
                    proto::node::NET_CUT => "cut",
                    proto::node::NET_HEAL => "heal",
                    _ => "unknown",
                };
                l.str("event", verb)
                    .str("by", "script")
                    .raw("from", &self.node_set(a[1]))
                    .raw("to", &self.node_set(a[2]))
                    .raw("both", if a[3] != 0 { "true" } else { "false" })
                    .num("ret", r.ret);
                "net"
            }
            // The seed's partitions (`sup::link`): [ordinal, shape, A, B, length, bridge].
            proto::ctl::DEC_NET_PART => {
                l = Line::at("net", k, r);
                l.str("event", "cut")
                    .str("by", "seed")
                    .num("n", a[0])
                    .str("shape", proto::node::shape_name(a[1]))
                    .raw("a", &self.node_set(a[2]))
                    .raw("b", &self.node_set(a[3]))
                    .num("length_ms", a[4] / 1_000_000);
                if a[1] == proto::node::SHAPE_BRIDGE {
                    l.raw("bridge", &self.node_set(a[5]));
                }
                "net"
            }
            proto::ctl::DEC_NET_PART_END => {
                l = Line::at("net", k, r);
                l.str("event", "heal").str("by", "seed").num("n", a[0]);
                "net"
            }
            proto::ctl::DEC_WIRE_DEAD => {
                l = Line::at("net", k, r);
                l.str("event", "forget")
                    .num("conn", a[0])
                    .str("side", if a[1] != 0 { "server" } else { "client" })
                    .str("name", &self.node_name(a[2]));
                "net"
            }
            // An unanswered keepalive probe (`sup::wire`): [conn, side, probes so far].
            proto::ctl::DEC_WIRE_PROBE => {
                l = Line::at("net", k, r);
                l.str("event", "probe")
                    .num("conn", a[0])
                    .str("side", if a[1] != 0 { "server" } else { "client" })
                    .num("unanswered", a[2]);
                "net"
            }
            proto::ctl::DEC_WIRE_HEAL => {
                l = Line::at("net", k, r);
                l.str("event", "release")
                    .num("conn", a[0])
                    .num("dir", a[1])
                    .num("until", a[2]);
                "net"
            }
            _ => return None,
        };
        self.node = None;
        Some(self.emit(ty, Some(r.seq), l))
    }

    /// An operation of a disk of node `node` (0: the driver's; with nodes, `node` names it).
    fn op(&mut self, k: usize, node: usize, names: &mut Names, o: &OpEv) -> Res<()> {
        self.node = (!self.nodes.is_empty()).then_some(node);
        let r = self.op_of(k, names, o);
        self.node = None;
        r
    }

    fn op_of(&mut self, k: usize, names: &mut Names, o: &OpEv) -> Res<()> {
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
        // A node's machine crash at its crash point: its point and what it lost are its
        // `downs` entry's (the run goes on; `node` names it).
        if let Some(n) = self.node.filter(|n| *n > 0) {
            let d = self.result.as_ref().and_then(|v| {
                v["nodes"]["list"][n]["downs"]
                    .as_array()?
                    .iter()
                    .find(|d| d["at_ms"] == r.vclock_ns / 1_000_000 && d["point"].is_u64())
                    .cloned()
            });
            if let Some(d) = d {
                l.num("ninc", d["incarnation"].as_u64().unwrap_or(0))
                    .num("point", d["point"].as_u64().unwrap_or(0));
                if d["lost"].is_object() {
                    l.raw("lost", &d["lost"].to_string());
                }
            }
            return self.emit("crash", Some(r.args[1]), l);
        }
        let c = self
            .result
            .as_ref()
            .and_then(|v| v["crashes"].as_array())
            .and_then(|a| a.iter().find(|c| c["incarnation"] == k as u64));
        if let Some(p) = c.and_then(|c| c["point"].as_u64()) {
            l.num("point", p);
        }
        // What a machine crash did to the work tree, as `faults.recent` shows it.
        if kind == "machine" {
            use crate::durability::kept;
            if let (Ok(live), Ok(Some(post))) = (kept::live(inc), kept::post_crash(inc)) {
                let lost = crate::launcher::attribution::lost(&live, &post, &self.work);
                l.raw("lost", &lost.to_string());
            }
        }
        self.emit("crash", Some(r.args[1]), l)
    }

    fn record(&mut self, k: usize, inc: &Path, recs: &mut Records, r: &Rec) -> Res<()> {
        if !self.nodes.is_empty() {
            self.node = Some(self.slot_node.get(&r.slot).copied().unwrap_or(0));
        }
        let res = match self.node_record(k, r) {
            Some(res) => res,
            None => self.record_of(k, inc, recs, r),
        };
        self.node = None;
        res
    }

    fn record_of(&mut self, k: usize, inc: &Path, recs: &mut Records, r: &Rec) -> Res<()> {
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
                // same label and text, the same hash); the label (and a mark's text) in clear.
                if (proto::sdk::OP_ASSERT..=proto::sdk::OP_DECLARE).contains(&a[0]) {
                    l.num("len", a[2].saturating_sub(proto::sdk::HDR_LEN as u64));
                    l.hex("hash", r.in_hash);
                }
                let strs = recs.strings(r)?;
                if let Some(s) = strs.first() {
                    l.num("pid", s.pid);
                }
                for s in &strs {
                    match s.which {
                        STR_LABEL => l.bytes("label", &s.bytes),
                        STR_TEXT => l.bytes("text", &s.bytes),
                        _ => &mut l,
                    };
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
                // The call's strings.
                let strs = recs.strings(r)?;
                if let Some(s) = strs.first() {
                    l.num("pid", s.pid);
                }
                let (mut argv, mut cut) = (vec![], false);
                for s in &strs {
                    match s.which {
                        STR_PATH => {
                            l.bytes("path", &s.bytes);
                        }
                        STR_PATH2 => {
                            l.bytes("path2", &s.bytes);
                        }
                        STR_RESOLVED => {
                            l.bytes("resolved", &s.bytes);
                        }
                        STR_RESOLVED2 => {
                            l.bytes("resolved2", &s.bytes);
                        }
                        STR_ARGV => {
                            cut |= s.cut;
                            argv.push(&s.bytes[..]);
                        }
                        STR_ARGV_CUT => cut = true,
                        _ => {}
                    }
                    if matches!(s.which, STR_PATH | STR_PATH2) && s.cut {
                        l.raw(
                            if s.which == STR_PATH {
                                "path_cut"
                            } else {
                                "path2_cut"
                            },
                            "true",
                        );
                    }
                }
                if !argv.is_empty() || cut {
                    l.list("argv", &argv);
                }
                if cut {
                    l.raw("argv_cut", "true");
                }
                self.emit("call", Some(r.seq), l)
            }
            Some(RecKind::Injected) => {
                let (n1, n2) = (recs.peek(0)?, recs.peek(1)?);
                let (_, mut e) = crate::launcher::attribution::injected(r, n1, n2);
                crate::launcher::attribution::name_link(&mut e, &self.nodes);
                // The network's faults are the supervisor's, on a link: no thread's node.
                if (proto::wire::INJ_NET_RESET..=proto::wire::INJ_NET_CUT).contains(&r.args[0]) {
                    self.node = None;
                }
                // A node's kill or machine crash by the seed: that node's.
                if r.args[0] == proto::node::INJ_NODE_KILL {
                    self.node = Some(r.args[1] as usize);
                }
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
            // An injected fault's names, read with it; a call's strings, read with it.
            Some(RecKind::Name | RecKind::Str) => Ok(()),
            Some(RecKind::SupDecision) if r.nr == Op::CrashPoint as u32 => self.crash(k, inc, r),
            // The end of a phase's command (`sup::phase`): [phase, wait word, next phase].
            Some(RecKind::SupDecision) if r.nr == proto::ctl::DEC_PHASE => {
                let mut l = Line::at("phase", k, r);
                l.str("ended", proto::ctl::phase_name(a[0]));
                let w = a[1] as i64;
                if w & 0x7f != 0 {
                    l.num("signal", (w & 0x7f) as u64);
                } else {
                    l.num("exit", ((w >> 8) & 0xff) as u64);
                }
                if a[2] != 0 {
                    l.str("next", proto::ctl::phase_name(a[2]));
                }
                self.emit("phase", Some(r.seq), l)
            }
            Some(RecKind::SupDecision) => {
                let mut l = Line::at("sched", k, r);
                let op = Op::from_u32(r.nr).map_or("unknown", |o| o.name());
                l.str("op", op).num("ret", r.ret);
                // A thread's first event (and an image's after execve): its process and
                // thread ids, so every later event of its slot has a process.
                if r.nr == Op::Hello as u32 {
                    l.num("pid", r.args[0]).num("tid", r.args[1]);
                }
                self.emit("sched", Some(r.seq), l)
            }
            Some(RecKind::Preempt) => {
                let mut l = Line::at("preempt", k, r);
                let why = match r.nr {
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
        let ops = Ops::open(inc)?;
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
        // The driver's disk, then each node's disks one after another (`node/NAME/inc-K/`):
        // their operations merged in the log's order.
        let mut streams = vec![Stream::new(0, ops.into_iter().collect(), self.work.clone())];
        if k == 0 {
            let run = inc.parent().unwrap_or(Path::new("."));
            for (n, name) in self.nodes.iter().enumerate().skip(1) {
                let mut disks = vec![];
                for d in crate::durability::check::incarnations(&run.join("node").join(name)) {
                    if let Some(o) = Ops::open(&d)? {
                        disks.push(o);
                    }
                }
                let at = self
                    .node_work
                    .get(n)
                    .cloned()
                    .unwrap_or_else(|| "/work".into());
                streams.push(Stream::new(n, disks, at));
            }
        }
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
            // A node's operation of an earlier call comes before it too: its machine crash at
            // a crash point has records at the same time as the operation before it. (The
            // driver's operations keep their order as without nodes.)
            while let Some(i) = first(&streams, |node, n| {
                (n.r.vclock_ns < r.vclock_ns
                    || (crash && n.r.vclock_ns == r.vclock_ns)
                    || (node > 0 && n.r.seq < r.seq))
                    && n.r.seq != r.seq
            }) {
                self.take_op(k, &mut streams[i])?;
            }
            self.record(k, inc, &mut recs, &r)?;
            // A call's operations follow it.
            if r.kind == RecKind::Trap as u8 {
                while let Some(i) = first(&streams, |_, n| n.r.seq == r.seq) {
                    self.take_op(k, &mut streams[i])?;
                }
            }
        }
        while let Some(i) = first(&streams, |_, _| true) {
            self.take_op(k, &mut streams[i])?;
        }
        Ok(())
    }

    fn take_op(&mut self, k: usize, s: &mut Stream) -> Res<()> {
        let n = s.take()?.unwrap();
        self.op(k, s.node, &mut s.names, &n)
    }
}

/// One node's disks' operation logs, read one after another (a disk's names are its own).
struct Stream {
    node: usize,
    disks: VecDeque<Ops>,
    names: Names,
    at: String,
    /// The disk before ended: its names go before the next disk's first operation (not
    /// before its own last one is named).
    ended: bool,
}

impl Stream {
    fn new(node: usize, disks: Vec<Ops>, at: String) -> Stream {
        Stream {
            node,
            // A disk with no operation would stall the ones after it.
            disks: disks.into_iter().filter(|o| o.next.is_some()).collect(),
            names: Names::new(at.clone()),
            at,
            ended: false,
        }
    }

    fn next(&self) -> Option<&OpEv> {
        self.disks.front().and_then(|o| o.next.as_ref())
    }

    fn take(&mut self) -> Res<Option<OpEv>> {
        if std::mem::take(&mut self.ended) {
            self.names = Names::new(self.at.clone());
        }
        let Some(o) = self.disks.front_mut() else {
            return Ok(None);
        };
        let n = o.take()?;
        if o.next.is_none() {
            self.disks.pop_front();
            self.ended = true;
        }
        Ok(n)
    }
}

/// The stream whose next operation comes first in the log (virtual time, then sequence
/// number) among those `ok` admits.
fn first(streams: &[Stream], ok: impl Fn(usize, &OpEv) -> bool) -> Option<usize> {
    streams
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.next().filter(|n| ok(s.node, n)).map(|n| (i, n)))
        .min_by_key(|(i, n)| (n.r.vclock_ns, n.r.seq, *i))
        .map(|(i, _)| i)
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
    let nodes: Vec<String> = cfg
        .as_ref()
        .and_then(|c| c["config"]["nodes"].as_array())
        .map(|ns| {
            std::iter::once("driver".to_string())
                .chain(
                    ns.iter()
                        .filter_map(|n| n["name"].as_str().map(str::to_string)),
                )
                .collect()
        })
        .unwrap_or_default();
    let node_work: Vec<String> = std::iter::once(work.clone())
        .chain(
            cfg.as_ref()
                .and_then(|c| c["config"]["nodes"].as_array())
                .into_iter()
                .flatten()
                .map(|n| n["work_at"].as_str().unwrap_or("/work").to_string()),
        )
        .collect();
    let mut x = Export {
        out: BufWriter::with_capacity(1 << 20, out),
        sel,
        result: crate::result::read_json(&run.join("result.json")).ok(),
        work,
        nodes,
        node_work,
        slot_node: HashMap::new(),
        node: None,
    };
    let mut l = Line(format!("{{\"type\":\"header\",\"v\":{VERSION}"));
    if let Some(s) = cfg.as_ref().and_then(|c| c["config"]["seed"].as_u64()) {
        l.num("seed", s);
    }
    l.str("work", &x.work.clone())
        .num("incarnations", incs.len());
    if !x.nodes.is_empty() {
        l.raw("nodes", &Value::from(x.nodes.clone()).to_string());
    }
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
