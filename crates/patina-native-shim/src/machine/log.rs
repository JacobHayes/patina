//! A child's page: a memory file the hub and the child both map, which the
//! child writes what it must not lose to as it happens. A child can end
//! anywhere, mid-quantum (a host fault, an abort) or under a lock no stop
//! path may take, so nothing it holds is shipped late: the hub reads the
//! page whenever it holds the baton, and once more when the child is gone.
//!
//! The page is a header and, for a recording child, its decision log after
//! it. The header holds how many bytes of decisions are committed, whether
//! the log filled, the child's time as of its latest runtime step (so a
//! child that dies mid-quantum leaves the machine at the time it reached),
//! and the compute-bound stop it took, if it took one (so its timeline
//! keeps the boundary its replay stops at). The hub writes the time once
//! before the child starts: the machine's time, which the child's clock
//! starts at.
//!
//! The decisions are one `[operation, outcome]` JSON pair per line. A
//! decision is committed only once whole, so a child that dies writing one
//! leaves the ones before it. The log is twice the trace budget
//! ([`patina_dst_trace::MAX_TRACE_BYTES`]) and sparse: a child that fills
//! it has outgrown the budget, and the root abandons the recording.

use super::*;
use patina_dst_abi::{Operation, Outcome};
use patina_dst_trace::ComputeStop;
use std::sync::atomic::{AtomicU64, AtomicUsize};

/// The header's words, in order.
const COMMITTED: usize = 0;
const FULL: usize = 1;
const NOW: usize = 2;
/// 0: no compute stop; 1: one with no task; 2: one with the task below.
const STOP: usize = 3;
const STOP_STEPS: usize = 4;
const STOP_TASK: usize = 5;
/// A replaying child: how many of its recorded decisions it consumed.
const CONSUMED: usize = 6;

/// The header's size.
const HEADER: usize = 64;

/// The page's size, header included.
const BYTES: usize = HEADER + 2 * patina_dst_trace::MAX_TRACE_BYTES as usize;

/// `map`ped `bytes` of `fd`, shared, or `None`.
fn map(fd: c_int, bytes: usize) -> Option<usize> {
    // SAFETY: a fresh shared mapping of a descriptor this process holds.
    let base = unsafe {
        crate::sud_host_syscall(
            libc::SYS_mmap,
            0,
            bytes as _,
            (libc::PROT_READ | libc::PROT_WRITE) as _,
            libc::MAP_SHARED as _,
            fd as _,
            0,
        )
    };
    (base > 0).then_some(base as usize)
}

/// Header word `index` of the page at `base`.
fn word(base: usize, index: usize) -> &'static AtomicU64 {
    // SAFETY: `base` is a live, page-aligned mapping of at least `HEADER`
    // bytes, which stays mapped while its owner lives; the words are only
    // ever accessed atomically.
    unsafe { &*((base + 8 * index) as *const AtomicU64) }
}

/// The hub's side of child `pid`'s page.
///
/// The child's guest code can write to the page as to any of its memory, so
/// the hub checks what it reads: a header no child of this shim writes is a
/// [`PageViolation`], never trusted.
pub(super) struct HubPage {
    base: usize,
    bytes: usize,
    /// How many committed bytes the hub has read.
    read: usize,
    /// How many decisions those bytes hold.
    decisions: u64,
    /// The latest time the hub read.
    now: u64,
}

/// A page header no child of this shim writes: what is wrong with it.
#[derive(Debug)]
pub(super) struct PageViolation(pub(super) String);

/// What the hub does with what a child recorded: the root's recording of it.
pub(super) trait ProcessRecording {
    /// The child's `decisions`, one JSON pair a line, since the last call.
    fn decisions(&mut self, decisions: &[u8]);
    /// The child's log filled: its decisions past those are missing.
    fn overflowed(&mut self);
    /// The child's compute-bound stop.
    fn compute_stop(&mut self, stop: ComputeStop);
}

impl HubPage {
    /// A fresh page whose time is `now`, and the descriptor (close-on-exec)
    /// the child maps it by.
    pub(super) fn create(now: u64) -> (Self, c_int) {
        Self::create_sized(now, BYTES)
    }

    fn create_sized(now: u64, bytes: usize) -> (Self, c_int) {
        // SAFETY: a static name; the flags are plain.
        let fd = unsafe {
            crate::sud_host_syscall(
                libc::SYS_memfd_create,
                c"patina-process-page".as_ptr() as _,
                libc::MFD_CLOEXEC as _,
                0,
                0,
                0,
                0,
            )
        } as c_int;
        // SAFETY: sizing the descriptor just made.
        if fd < 0
            || unsafe {
                crate::sud_host_syscall(libc::SYS_ftruncate, fd as _, bytes as _, 0, 0, 0, 0)
            } != 0
        {
            protocol_fatal_text("creating a process's page failed");
        }
        let base = map(fd, bytes)
            .unwrap_or_else(|| protocol_fatal_text("mapping a process's page failed"));
        word(base, NOW).store(now, Ordering::Release);
        (
            Self {
                base,
                bytes,
                read: 0,
                decisions: 0,
                now,
            },
            fd,
        )
    }

    /// Hand `recording` what the child recorded since the last call: its
    /// decisions, whether its log filled (decisions are missing past them),
    /// and the compute-bound stop it took. The child is frozen or gone
    /// while the hub reads.
    pub(super) fn collect(
        &mut self,
        recording: &mut impl ProcessRecording,
    ) -> Result<(), PageViolation> {
        let committed = word(self.base, COMMITTED).load(Ordering::Acquire);
        let room = (self.bytes - HEADER) as u64;
        if committed < self.read as u64 || committed > room {
            return Err(PageViolation(format!(
                "its log's committed length {committed} is outside {}..={room}",
                self.read
            )));
        }
        let committed = committed as usize;
        let start = self.base + HEADER + self.read;
        // SAFETY: inside the mapping, past what was read, up to what the
        // child committed (checked above).
        let decisions =
            unsafe { std::slice::from_raw_parts(start as *const u8, committed - self.read) };
        self.read = committed;
        self.decisions += decisions.iter().filter(|byte| **byte == b'\n').count() as u64;
        let full = word(self.base, FULL).load(Ordering::Acquire) != 0;
        let stop = self.compute_stop(full)?;
        if !decisions.is_empty() {
            recording.decisions(decisions);
        }
        if full {
            recording.overflowed();
        }
        if let Some(stop) = stop {
            recording.compute_stop(stop);
        }
        Ok(())
    }

    /// The compute-bound stop the child took, if it took one; a whole log
    /// holds the decisions it stopped after.
    fn compute_stop(&self, full: bool) -> Result<Option<ComputeStop>, PageViolation> {
        let task = match word(self.base, STOP).load(Ordering::Acquire) {
            0 => return Ok(None),
            1 => None,
            2 => Some(TaskId(word(self.base, STOP_TASK).load(Ordering::Acquire))),
            other => {
                return Err(PageViolation(format!("its compute stop is marked {other}")));
            }
        };
        let steps = word(self.base, STOP_STEPS).load(Ordering::Acquire);
        if !full && steps > self.decisions {
            return Err(PageViolation(format!(
                "its compute stop is after step {steps}, past its {} decisions",
                self.decisions
            )));
        }
        Ok(Some(ComputeStop { steps, task }))
    }

    /// The child's time as of its latest runtime step: never before what
    /// the hub read last, nor before `floor`, the machine's time when the
    /// child last took the baton.
    pub(super) fn now(&mut self, floor: u64) -> Result<u64, PageViolation> {
        let now = word(self.base, NOW).load(Ordering::Acquire);
        if now < self.now.max(floor) {
            return Err(PageViolation(format!(
                "its time {now} is before {}",
                self.now.max(floor)
            )));
        }
        self.now = now;
        Ok(now)
    }

    /// A replaying child: how many of its recorded decisions it consumed
    /// as of its latest runtime step.
    pub(super) fn consumed(&self) -> u64 {
        word(self.base, CONSUMED).load(Ordering::Acquire)
    }
}

impl Drop for HubPage {
    fn drop(&mut self) {
        // SAFETY: unmaps this page's own mapping.
        unsafe {
            crate::sud_host_syscall(
                libc::SYS_munmap,
                self.base as _,
                self.bytes as _,
                0,
                0,
                0,
                0,
            )
        };
    }
}

/// This child's page, mapped at startup (0 in the root).
static PAGE: AtomicUsize = AtomicUsize::new(0);

/// Map the page the hub handed this child, as descriptor `fd`: answers the
/// machine's time the hub wrote there, which this child's clock starts at.
pub(super) fn open(fd: c_int) -> Option<u64> {
    let base = map(fd, BYTES)?;
    close(fd);
    PAGE.store(base, Ordering::Release);
    Some(word(base, NOW).load(Ordering::Acquire))
}

/// This child as of its latest runtime step: its time is `now`, and,
/// replaying, it consumed `consumed` recorded decisions.
pub(crate) fn note_step(now: u64, consumed: Option<u64>) {
    let base = PAGE.load(Ordering::Relaxed);
    if base != 0 {
        word(base, NOW).fetch_max(now, Ordering::Release);
        if let Some(consumed) = consumed {
            word(base, CONSUMED).store(consumed, Ordering::Release);
        }
    }
}

/// A recording child's trace channel: every decision goes to its page's
/// log as it is recorded, a compute-bound stop goes to the page's header,
/// and nothing is written at its end (the root writes the run's trace).
pub(crate) struct DecisionLog {
    written: usize,
}

impl DecisionLog {
    /// The log of the page this child mapped at startup.
    pub(crate) fn new() -> Result<Self, patina_dst_runtime::RuntimeError> {
        if PAGE.load(Ordering::Acquire) == 0 {
            return Err(patina_dst_runtime::RuntimeError::Config(format!(
                "a recording child process requires {}",
                patina_dst_runtime::ENV_PROCESS_PAGE_FD
            )));
        }
        Ok(Self { written: 0 })
    }

    fn base() -> usize {
        PAGE.load(Ordering::Acquire)
    }
}

impl patina_dst_runtime::TraceTransport for DecisionLog {
    fn read_bundle(&mut self) -> std::io::Result<Vec<u8>> {
        Err(std::io::Error::other(
            "a recording child process reads no trace",
        ))
    }
    fn write_bundle(&mut self, _bytes: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    /// A stop's flush: the decisions are all in the log already; a
    /// compute-bound stop's boundary goes to the header (no allocation).
    fn write_prefix(&mut self, recorder: &patina_dst_trace::Recorder) -> std::io::Result<()> {
        if let Some(stop) = recorder.metadata().compute_stop {
            let base = Self::base();
            word(base, STOP_STEPS).store(stop.steps, Ordering::Relaxed);
            word(base, STOP_TASK).store(stop.task.map_or(0, |task| task.0), Ordering::Relaxed);
            word(base, STOP).store(if stop.task.is_some() { 2 } else { 1 }, Ordering::Release);
        }
        Ok(())
    }
    fn decision(&mut self, operation: &Operation, outcome: &Outcome) {
        Self::append(Self::base(), BYTES, &mut self.written, operation, outcome);
    }
}

impl DecisionLog {
    fn append(
        base: usize,
        bytes: usize,
        written: &mut usize,
        operation: &Operation,
        outcome: &Outcome,
    ) {
        if word(base, FULL).load(Ordering::Relaxed) != 0 {
            return;
        }
        // SAFETY: the mapping's room past what is written.
        let room = unsafe {
            std::slice::from_raw_parts_mut(
                (base + HEADER + *written) as *mut u8,
                bytes - HEADER - *written,
            )
        };
        let mut cursor = std::io::Cursor::new(room);
        let fits = serde_json::to_writer(&mut cursor, &(operation, outcome)).is_ok()
            && std::io::Write::write_all(&mut cursor, b"\n").is_ok();
        if !fits {
            word(base, FULL).store(1, Ordering::Release);
            return;
        }
        *written += cursor.position() as usize;
        word(base, COMMITTED).store(*written as u64, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the hub handed the root's recording.
    #[derive(Default)]
    struct Recorded {
        decisions: Vec<u8>,
        abandoned: bool,
        stop: Option<ComputeStop>,
    }

    impl ProcessRecording for Recorded {
        fn decisions(&mut self, decisions: &[u8]) {
            self.decisions.extend_from_slice(decisions);
        }
        fn overflowed(&mut self) {
            self.abandoned = true;
        }
        fn compute_stop(&mut self, stop: ComputeStop) {
            self.stop = Some(stop);
        }
    }

    fn append(hub: &HubPage, written: &mut usize, count: usize) {
        for _ in 0..count {
            DecisionLog::append(
                hub.base,
                hub.bytes,
                written,
                &Operation::SchedulerNext,
                &Outcome::Unit,
            );
        }
    }

    /// A log that fills abandons the root's recording of the child, which
    /// keeps every decision committed before.
    #[test]
    fn a_full_log_abandons_the_recording() {
        let (mut hub, fd) = HubPage::create_sized(7, HEADER + 64);
        close(fd);
        let mut written = 0;
        append(&hub, &mut written, 10);
        let mut recorded = Recorded::default();
        hub.collect(&mut recorded).unwrap();
        assert!(recorded.abandoned);
        let lines = recorded
            .decisions
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty());
        assert!(lines.count() >= 1);
    }

    /// A header no child writes (its guest code scribbled on the page) is a
    /// violation, never read as the child's.
    #[test]
    fn a_page_no_child_writes_is_a_violation() {
        let plant = |plant: &dyn Fn(usize)| {
            let (mut hub, fd) = HubPage::create_sized(7, HEADER + 4096);
            close(fd);
            let mut written = 0;
            append(&hub, &mut written, 3);
            hub.collect(&mut Recorded::default()).unwrap();
            plant(hub.base);
            hub.collect(&mut Recorded::default())
                .and_then(|()| hub.now(7).map(drop))
                .is_err()
        };
        let set = |index: usize, value: u64| {
            move |base: usize| word(base, index).store(value, Ordering::Relaxed)
        };
        let wrong: Vec<&str> = [
            ("committed shrank", &set(COMMITTED, 1) as &dyn Fn(usize)),
            ("committed past the log", &set(COMMITTED, 1 << 40)),
            ("stop marked 3", &set(STOP, 3)),
            ("stop past the decisions", &|base| {
                set(STOP_STEPS, 4)(base);
                set(STOP, 1)(base);
            }),
            ("time before the start", &set(NOW, 6)),
        ]
        .into_iter()
        .filter(|(_, planted)| !plant(*planted))
        .map(|(name, _)| name)
        .collect();
        assert!(wrong.is_empty(), "accepted: {wrong:?}");
        // The child's own writes are no violation.
        assert!(!plant(&|base| {
            set(STOP_STEPS, 3)(base);
            set(STOP, 1)(base);
            set(NOW, 9)(base);
        }));
    }
}
