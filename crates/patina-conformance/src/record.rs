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

    /// Emit through C stdio's `stdout` instead of the recorder's own
    /// descriptor writes, and leave it unflushed: the line reaches the
    /// stream only when libc writes the stream's buffer out — onto a pipe,
    /// at the latest when `exit` flushes it after the atexit handlers.
    pub fn emit_through_stdio(self) {
        self.recorder.emit_with(self.event, |line| {
            let line = std::ffi::CString::new(line).expect("an event line holds no NUL");
            // SAFETY: the process's C `stdout` and a NUL-terminated line.
            let r = unsafe { libc::fputs(line.as_ptr(), C_STDOUT) };
            assert!(r >= 0, "fputs to stdout failed");
        });
    }
}

unsafe extern "C" {
    /// C stdio's `stdout` (the shim's sentinel under patina).
    #[link_name = "stdout"]
    static mut C_STDOUT: *mut libc::FILE;
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

    pub fn emit(&self, event: Event) {
        self.emit_with(event, |line| {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            out.write_all(line).expect("stdout write");
            out.flush().expect("stdout flush");
        });
    }

    /// Number `event`, journal it, and hand its line (newline included) to
    /// `write`.
    fn emit_with(&self, mut event: Event, write: impl FnOnce(&[u8])) {
        if QUIET.with(std::cell::Cell::get) != 0 {
            return;
        }
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        event.seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let mut line = serde_json::to_string(&event).expect("event serializes");
        crate::journal::append(line.as_bytes());
        line.push('\n');
        write(line.as_bytes());
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
