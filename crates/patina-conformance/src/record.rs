//! The JSONL recorder a scenario writes its events through.

use crate::observe::{Event, Norm};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

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

    /// Declare a normalization for a field path (`ret`, `errno`, `args.<k>`,
    /// `fields.<k>`).
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
