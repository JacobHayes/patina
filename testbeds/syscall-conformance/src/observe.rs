//! Typed observation events and the JSONL recorder.
//!
//! One event per observed call: `{"seq","op","args","ret","errno","fields",
//! "norm"}`. `args` are the inputs the probe chose to show, `ret` is the kernel
//! result (`-1` with `errno` named on failure), `fields` are the struct members
//! the probe pulled out, and `norm` maps a field path (`ret`, `args.fd`,
//! `fields.st_ino`) to the typed normalization the differ applies before
//! comparing host and patina streams (see [`Norm`]). Events go to stdout; asserts
//! and panics go to stderr, so a stream is machine-readable even when the probe
//! dies.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Event {
    pub seq: u64,
    pub op: String,
    pub args: BTreeMap<String, Value>,
    pub ret: Value,
    pub errno: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub norm: BTreeMap<String, String>,
}

/// Per-field normalization, declared by the probe, never regex over text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Norm {
    /// The value is an allocated number (a descriptor, a port) whose identity
    /// matters but whose magnitude is the host's business: replaced by the
    /// ordinal of first appearance within the namespace, so sharing relations
    /// survive and absolute numbers do not. In the `fd` namespace a `close`
    /// retires the number, so a later reuse is a NEW identity on both sides;
    /// the lowest-free reuse policy itself is a probe `check`, not a stream
    /// property.
    Relative(&'static str),
    /// An inode number: ordinal by first appearance (identity relations only).
    Inode,
    /// Host identity (pid/uid/gid): ordinal by first appearance.
    Identity,
    /// A clock reading: replaced by its order relation to the previous reading
    /// of the same `(op, field)` (`mono:first`, `mono:>=`, `mono:-`). Strict
    /// advance between two reads is not a kernel guarantee (coarse clocks, and
    /// a virtual clock that only moves on sleeps), so "advanced" is a probe
    /// `check`, not a stream property.
    Monotonic,
    /// Keep only these bits.
    Mask(u64),
}

impl Norm {
    pub fn tag(&self) -> String {
        match self {
            Norm::Relative(namespace) => format!("relative:{namespace}"),
            Norm::Inode => "inode".to_string(),
            Norm::Identity => "identity".to_string(),
            Norm::Monotonic => "monotonic".to_string(),
            Norm::Mask(bits) => format!("mask:0o{bits:o}"),
        }
    }

    pub fn parse(tag: &str) -> Option<ParsedNorm> {
        if let Some(namespace) = tag.strip_prefix("relative:") {
            return Some(ParsedNorm::Relative(namespace.to_string()));
        }
        if let Some(octal) = tag.strip_prefix("mask:0o") {
            return u64::from_str_radix(octal, 8).ok().map(ParsedNorm::Mask);
        }
        match tag {
            "inode" => Some(ParsedNorm::Inode),
            "identity" => Some(ParsedNorm::Identity),
            "monotonic" => Some(ParsedNorm::Monotonic),
            _ => None,
        }
    }
}

/// [`Norm`] as read back from a stream (owned namespace).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedNorm {
    Relative(String),
    Inode,
    Identity,
    Monotonic,
    Mask(u64),
}

/// A builder for one event; `emit` hands it to the recorder.
pub struct EventBuilder<'a> {
    recorder: &'a Recorder,
    event: Event,
}

impl EventBuilder<'_> {
    pub fn arg(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.event.args.insert(key.to_string(), value.into());
        self
    }

    pub fn field(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.event.fields.insert(key.to_string(), value.into());
        self
    }

    /// Declare a normalization for a field path (`ret`, `args.<k>`, `fields.<k>`).
    pub fn norm(mut self, path: &str, norm: Norm) -> Self {
        self.event.norm.insert(path.to_string(), norm.tag());
        self
    }

    pub fn emit(self) {
        self.recorder.emit(self.event);
    }
}

/// The process-wide JSONL writer. Thread-safe: managed threads under patina and
/// host threads natively both append through the same lock, so `seq` is a
/// total order over the stream.
pub struct Recorder {
    seq: AtomicU64,
    lock: Mutex<()>,
}

thread_local! {
    /// Depth of [`Recorder::quiet`] on THIS thread. Per thread, not per
    /// process: a helper thread's quiet window must never swallow an event the
    /// thread under test emits meanwhile.
    static QUIET: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

impl Recorder {
    pub fn new() -> Self {
        Recorder {
            seq: AtomicU64::new(0),
            lock: Mutex::new(()),
        }
    }

    /// Start an event for `op` with the kernel-style `result` (`-errno` < 0).
    pub fn event(&self, op: &str, result: i64) -> EventBuilder<'_> {
        let (ret, errno) = if result < 0 {
            (
                Value::from(-1),
                Some(crate::vehicle::errno_name((-result) as i32)),
            )
        } else {
            (Value::from(result), None)
        };
        EventBuilder {
            recorder: self,
            event: Event {
                seq: 0,
                op: op.to_string(),
                args: BTreeMap::new(),
                ret,
                errno,
                fields: BTreeMap::new(),
                norm: BTreeMap::new(),
            },
        }
    }

    pub fn emit(&self, mut event: Event) {
        if QUIET.with(std::cell::Cell::get) != 0 {
            return;
        }
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        event.seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let line = serde_json::to_string(&event).expect("event serializes");
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        out.write_all(line.as_bytes()).expect("stdout write");
        out.write_all(b"\n").expect("stdout write");
        out.flush().expect("stdout flush");
    }

    /// Run `body` with this thread's recording suspended (setup/teardown and
    /// racy loops whose iteration count is not a property under test). Other
    /// threads keep recording.
    pub fn quiet<T>(&self, body: impl FnOnce() -> T) -> T {
        QUIET.with(|depth| depth.set(depth.get() + 1));
        let value = body();
        QUIET.with(|depth| depth.set(depth.get() - 1));
        value
    }
}

/// Parse a raw or blessed stream: one JSON event per line, `#` comments and blank
/// lines ignored, an optional leading header object (`{"header":{...}}`) skipped.
pub fn parse_stream(text: &str) -> Result<Vec<Event>, String> {
    let mut events = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("{\"header\"") {
            continue;
        }
        let event: Event = serde_json::from_str(line)
            .map_err(|error| format!("line {}: not an event: {error}: {line}", index + 1))?;
        events.push(event);
    }
    Ok(events)
}
